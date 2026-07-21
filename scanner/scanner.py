from datetime import datetime, timezone
import re
import socket
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

from .control import check_stop
from .net import http_request, make_session, normalize_url, validate_input_url
from .options import ScanOptions
from .page_scan import scan_pages
from .scan_progress import ScanProgress
from .security_score import calculate_score

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
SENSITIVE_PATHS = [
    "/admin",
    "/admin/login",
    "/backup",
    "/.env",
    "/.git/HEAD",
    "/test",
    "/test/login",
    "/debug",
    "/api/docs",
    "/phpinfo.php",
    "/server-status",
    "/swagger",
    "/swagger-ui",
    "/actuator",
    "/console",
    "/docs"
]
SERVER_NAME_RE = re.compile(r"(?i)\b(?:apache|nginx|iis|openresty|tomcat)\b")  # 匹配常见的服务器名称。
FRAMEWORK_NAME_RE = re.compile(r"(?i)\b(?:php|asp\.net|express|django|spring|laravel|rails|koa|fastapi|flask)\b")  # 匹配常见的框架名称。
VERSION_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")  # 匹配常见的版本号格式。


def field_exposes_version(value: str, name_re: re.Pattern[str]) -> bool:
    """判断文本是否同时包含技术栈名称和版本号。"""
    return bool(value and name_re.search(value) and VERSION_NUMBER_RE.search(value))


def check_https(url: str) -> bool:
    """判断最终地址是否走 HTTPS。"""
    return url.startswith("https://")


def check_ssl_via_requests(response: requests.Response) -> Tuple[bool, int]:
    """基于已建立连接判断 SSL 是否有效并估算剩余天数。"""
    try:
        if not response.url.startswith("https://"):
            return False, -1

        # 不同 requests 适配层级下，证书对象路径可能不同。
        cert = None
        try:
            cert = response.raw.connection.sock.getpeercert()
        except Exception:
            cert = None

        if not cert:
            # HTTPS 请求成功但拿不到证书详情，依然视为 SSL 有效
            return True, -1

        not_after = cert.get("notAfter")
        if not not_after:
            return True, -1

        expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expire_dt - datetime.now(timezone.utc)).days
        return True, days_left
    except Exception:
        return False, -1


def resolve_host_ips(host: str) -> List[str]:
    """解析主机名对应的 IP 地址。"""
    if not host:
        return []

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []

    ips = []
    for info in infos:
        address = info[4][0]
        if address not in ips:
            ips.append(address)
    return ips


def scan(
    url: str,
    progress_callback=None,
    options: Dict[str, Any] | ScanOptions | None = None,
    stop_event=None,
) -> Dict[str, Any]:
    """执行主站点安全扫描。"""
    scan_options = options if isinstance(options, ScanOptions) else ScanOptions.from_dict(options)

    if scan_options.enabled_items() == 0:
        return {
            "ok": False,
            "error": "请至少启用一项检测后再开始扫描。",
        }

    progress = ScanProgress(scan_options, len(SENSITIVE_PATHS), progress_callback, stop_event=stop_event)

    session = make_session()
    errors: List[str] = []

    ok, msg = validate_input_url(url)
    if not ok:
        return {"ok": False, "error": msg}

    check_stop(stop_event)
    # 先尝试 HTTPS，再回退到 HTTP。
    normalized_url = normalize_url(url, session)
    parsed = urlparse(normalized_url)
    host = parsed.hostname or ""
    resolved_ips = resolve_host_ips(host)

    result: Dict[str, Any] = {
        "ok": True,
        "url": normalized_url,
        "host": host,
        "resolved_ips": resolved_ips,
        "https": False,
        "ssl_valid": False,
        "ssl_days_left": -1,
        "security_header_score": 0,
        "missing_security_headers": [],
        "trace_enabled": None,
        "sensitive_paths": [],
        "info_leak": {
            "version_exposed": None,
            "framework_exposed": None,
        },
        "errors": []
    }

    # 1. 主请求
    progress.update("正在请求目标站点")
    try:
        resp = http_request(session, "GET", normalized_url, stream=True, raise_for_status=True)
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "未知"
        return {"ok": False, "error": f"目标站点返回异常状态码：{code}"}
    except Exception as e:
        return {"ok": False, "error": f"目标站点不可访问：{e}"}

    progress.update("目标站点请求完成", 1)

    # 2. HTTPS / SSL
    check_stop(stop_event)
    result["https"] = check_https(resp.url)
    result["https_checked"] = scan_options.check_https
    if scan_options.check_https:
        progress.update("正在检测 HTTPS", 1)

    if scan_options.check_ssl:
        ssl_valid, ssl_days_left = check_ssl_via_requests(resp)
        result["ssl_valid"] = ssl_valid
        result["ssl_days_left"] = ssl_days_left
        progress.update("正在检测 SSL 证书", 1)
    else:
        result["ssl_valid"] = None
        result["ssl_days_left"] = None

    # 3. 安全响应头 + 信息泄露
    check_stop(stop_event)
    headers = resp.headers
    if scan_options.check_security_headers:
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        result["missing_security_headers"] = missing
        result["security_header_score"] = (len(SECURITY_HEADERS) - len(missing)) * 5
    else:
        result["missing_security_headers"] = None
        result["security_header_score"] = None
    if scan_options.check_security_headers:
        progress.update("正在检测 HTTP 安全头", 1)

    if scan_options.check_info_leak:
        server = headers.get("Server", "")
        x_powered_by = headers.get("X-Powered-By", "")
        aspnet_version = headers.get("X-AspNet-Version", "")
        # 分字段判断
        result["info_leak"]["version_exposed"] = bool(
            field_exposes_version(server, SERVER_NAME_RE)
            or field_exposes_version(x_powered_by, FRAMEWORK_NAME_RE)
            or (aspnet_version and VERSION_NUMBER_RE.search(aspnet_version))
        )
        result["info_leak"]["framework_exposed"] = bool(x_powered_by and FRAMEWORK_NAME_RE.search(x_powered_by))
    else:
        result["info_leak"]["version_exposed"] = None
        result["info_leak"]["framework_exposed"] = None
    if scan_options.check_info_leak:
        progress.update("正在检测响应头暴露信息", 1)

    # 4. TRACE 检测
    if scan_options.check_trace:
        check_stop(stop_event)
        try:
            trace_resp = http_request(session, "TRACE", normalized_url, allow_redirects=False)
            result["trace_enabled"] = trace_resp.status_code < 400
        except Exception as e:
            result["trace_enabled"] = None
            errors.append(f"TRACE 检测异常：{e}")
        progress.update("正在检测 TRACE 方法", 1)
    else:
        result["trace_enabled"] = None

    # 5. 敏感路径检测
    if scan_options.check_sensitive_paths:
        found_paths = []
        base = f"{parsed.scheme}://{parsed.netloc}"
        for p in SENSITIVE_PATHS:
            check_stop(stop_event)
            test_url = base + p
            try:
                r = http_request(session, "GET", test_url, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    found_paths.append(p)
            except Exception as e:
                errors.append(f"敏感路径 {p} 检测异常：{e}")
            progress.update(f"正在检测敏感路径：{p}", 1)
        result["sensitive_paths"] = found_paths
    else:
        result["sensitive_paths"] = None

    if scan_options.check_page_scan:
        check_stop(stop_event)
        result["page_scan"] = scan_pages(
            session,
            normalized_url,
            scan_options,
            max_pages=scan_options.page_scan_max_pages,
            max_depth=scan_options.page_scan_max_depth,
            progress_callback=progress.page_callback(scan_options),
            stop_event=stop_event,
        )
        progress.complete_page_scan(scan_options)
    else:
        result["page_scan"] = None

    # 7. 评分
    check_stop(stop_event)
    progress.update("正在整理检测结果")
    score, level = calculate_score(result, scan_options)
    result["score"] = score
    result["level"] = level
    page_scan = result.get("page_scan")
    if page_scan is not None:
        result["page_scan_summary"] = {
            "enabled": True,
            "pages_scanned": page_scan.get("pages_scanned", 0),
            "finding_count": page_scan.get("finding_count", 0),
            "highest_risk": page_scan.get("highest_risk", "无"),
        }
    else:
        result["page_scan_summary"] = {
            "enabled": False,
            "pages_scanned": 0,
            "finding_count": 0,
            "highest_risk": "无",
        }

    result["errors"] = errors
    check_stop(stop_event)
    progress.update("检测完成", 1)
    return result

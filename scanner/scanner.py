import requests
from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse
import re

from .net import http_request, make_session, normalize_url, validate_input_url
from .options import ScanOptions
from .page_scan import scan_pages

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
VERSION_HINT_RE = re.compile(r"(?i)(?:\b(?:apache|nginx|iis|openresty|tomcat|php|asp\.net|express|django|spring|laravel|rails|koa|fastapi|flask)\b.*\b\d+(?:\.\d+){0,2}\b|\b\d+(?:\.\d+){1,3}\b.*\b(?:apache|nginx|iis|openresty|tomcat|php|asp\.net|express|django|spring|laravel|rails|koa|fastapi|flask)\b)")
# version_hint_re 用于检测服务器响应头或页面源码中是否暴露了版本信息，匹配常见的 Web 服务器和框架名称及其版本号。

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

        expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_dt - datetime.utcnow()).days
        return True, days_left
    except Exception:
        return False, -1


def calculate_score(result: Dict[str, Any], options: ScanOptions) -> Tuple[int, str]:
    """计算安全评分和等级。"""
    score = 0
    max_score = 0

    if options.check_https:
        max_score += 10
        if result.get("https"):
            score += 10

    if options.check_ssl:
        max_score += 20
        if result.get("ssl_valid"):
            score += 10

        days_left = result.get("ssl_days_left", -1)
        if isinstance(days_left, int) and days_left > 7:
            score += 10

    if options.check_security_headers:
        max_score += 30
        # 每个安全头按 5 分累计。
        header_score = result.get("security_header_score", 0) or 0
        score += header_score

    if options.check_info_leak:
        max_score += 20
        info_leak = result.get("info_leak", {})
        if info_leak.get("version_exposed") is False:
            score += 10
        if info_leak.get("framework_exposed") is False:
            score += 10

    if options.check_trace:
        max_score += 10
        if result.get("trace_enabled") is False:
            score += 10

    if options.check_sensitive_paths:
        max_score += 10
        if not result.get("sensitive_paths"):
            score += 10

    if max_score > 0:
        score = round((score / max_score) * 100)

    if score >= 85:
        level = "A级"
    elif score >= 70:
        level = "B级"
    else:
        level = "C级"

    return score, level


def scan(url: str, progress_callback=None, options: Dict[str, Any] | ScanOptions | None = None) -> Dict[str, Any]:
    """执行主站点安全扫描。"""
    scan_options = options if isinstance(options, ScanOptions) else ScanOptions.from_dict(options)

    if scan_options.enabled_items() == 0:
        return {
            "ok": False,
            "error": "请至少启用一项检测后再开始扫描。",
        }

    def update_progress(p: int, text: str):
        if progress_callback:
            progress_callback(p, text)

    session = make_session()
    errors: List[str] = []

    ok, msg = validate_input_url(url)
    if not ok:
        return {"ok": False, "error": msg}

    # 先尝试 HTTPS，再回退到 HTTP。
    normalized_url = normalize_url(url, session)
    parsed = urlparse(normalized_url)
    host = parsed.hostname or ""

    result: Dict[str, Any] = {
        "ok": True,
        "url": normalized_url,
        "host": host,
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
    update_progress(10, "正在请求目标站点")
    try:
        resp = http_request(session, "GET", normalized_url, stream=True)
    except Exception as e:
        return {"ok": False, "error": f"目标站点不可访问：{e}"}

    # 2. HTTPS / SSL
    update_progress(25, "正在检测 HTTPS 与 SSL")
    result["https"] = check_https(resp.url)
    result["https_checked"] = scan_options.check_https

    if scan_options.check_ssl:
        ssl_valid, ssl_days_left = check_ssl_via_requests(resp)
        result["ssl_valid"] = ssl_valid
        result["ssl_days_left"] = ssl_days_left
    else:
        result["ssl_valid"] = None
        result["ssl_days_left"] = None

    # 3. 安全响应头 + 信息泄露
    update_progress(45, "正在检测 HTTP 安全头与信息泄露")
    headers = resp.headers
    if scan_options.check_security_headers:
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        result["missing_security_headers"] = missing
        result["security_header_score"] = (len(SECURITY_HEADERS) - len(missing)) * 5
    else:
        result["missing_security_headers"] = None
        result["security_header_score"] = None

    if scan_options.check_info_leak:
        server = headers.get("Server", "")
        x_powered_by = headers.get("X-Powered-By", "")
        response_banner = " ".join(
            part for part in (server, x_powered_by, resp.headers.get("X-AspNet-Version", "")) if part
        )
        result["info_leak"]["version_exposed"] = bool(VERSION_HINT_RE.search(response_banner))
        result["info_leak"]["framework_exposed"] = bool(
            x_powered_by
            and (
                VERSION_HINT_RE.search(x_powered_by)
                or any(name in x_powered_by.lower() for name in ("express", "django", "spring", "laravel", "rails", "koa", "fastapi", "flask"))
            )
        )
    else:
        result["info_leak"]["version_exposed"] = None
        result["info_leak"]["framework_exposed"] = None

    # 4. TRACE 检测
    update_progress(60, "正在检测 TRACE 方法")
    if scan_options.check_trace:
        try:
            trace_resp = http_request(session, "TRACE", normalized_url, allow_redirects=False)
            result["trace_enabled"] = trace_resp.status_code < 400
        except Exception as e:
            result["trace_enabled"] = None
            errors.append(f"TRACE 检测异常：{e}")
    else:
        result["trace_enabled"] = None

    # 5. 敏感路径检测
    update_progress(75, "正在检测敏感路径")
    if scan_options.check_sensitive_paths:
        found_paths = []
        base = f"{parsed.scheme}://{parsed.netloc}"
        for p in SENSITIVE_PATHS:
            test_url = base + p
            try:
                r = http_request(session, "GET", test_url, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    found_paths.append(p)
            except Exception as e:
                errors.append(f"敏感路径 {p} 检测异常：{e}")
        result["sensitive_paths"] = found_paths
    else:
        result["sensitive_paths"] = None

    # 页面级扫描放在主站检测之后执行。
    update_progress(80, "正在整理检测结果")

    if scan_options.check_page_scan:
        update_progress(70, "正在执行页面级安全检查")
        result["page_scan"] = scan_pages(
            session,
            normalized_url,
            scan_options,
            max_pages=scan_options.page_scan_max_pages,
            max_depth=scan_options.page_scan_max_depth,
            progress_callback=progress_callback,
        )
    else:
        result["page_scan"] = None

    # 7. 评分
    score, level = calculate_score(result, scan_options)
    result["score"] = score
    result["level"] = level
    page_scan = result.get("page_scan")
    if page_scan is not None:
        result["page_scan_summary"] = {
            "enabled": True,
            "pages_scanned": page_scan.get("pages_scanned", 0),
            "finding_count": page_scan.get("finding_count", 0),
            "highest_risk": page_scan.get("highest_risk", "低"),
        }
    else:
        result["page_scan_summary"] = {
            "enabled": False,
            "pages_scanned": 0,
            "finding_count": 0,
            "highest_risk": "低",
        }

    result["errors"] = errors
    update_progress(100, "检测完成")
    return result

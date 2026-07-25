import ipaddress
import re
import socket
from collections.abc import Mapping
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import dns.exception
import dns.resolver
from bs4 import BeautifulSoup
from bs4.element import Tag
import requests

from scanner.tls import inspect_tls_configuration
from utils.control import check_stop
from utils.net import http_request, make_session, normalize_url, validate_input_url
from utils.timer import Timer
from .options import ScanOptions
from .pagecheck.page_scan import scan_pages
from utils.scan_progress import ScanProgress
from utils.security_score import calculate_score

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]
INFO_LEAK_META_KEYS = {
    "generator",
    "application-name",
    "og:site_name",
    "author",
    "copyright",
    "version",
    "build",
    "release",
    "app-version",
}
GENERIC_META_VALUES = {
    "",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "default",
    "website",
    "web",
    "page",
    "homepage",
    "home",
    "首页",
    "站点",
}
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


def _create_scan_context(
    url: str,
    progress_callback=None,
    options: Dict[str, Any] | ScanOptions | None = None,
    stop_event=None,
) -> Dict[str, Any]:
    """初始化扫描上下文。"""
    scan_options = options if isinstance(options, ScanOptions) else ScanOptions.from_dict(options)
    if scan_options.enabled_items() == 0:
        return {
            "ok": False,
            "error": "请至少启用一项检测后再开始扫描。",
        }

    ok, msg = validate_input_url(url)
    if not ok:
        return {"ok": False, "error": msg}

    progress = ScanProgress(scan_options, len(SENSITIVE_PATHS), progress_callback, stop_event=stop_event)
    session = make_session()

    check_stop(stop_event)
    normalized_url = normalize_url(url, session)
    parsed = urlparse(normalized_url)
    host = parsed.hostname or ""

    return {
        "ok": True,
        "scan_options": scan_options,
        "progress": progress,
        "session": session,
        "normalized_url": normalized_url,
        "parsed": parsed,
        "host": host,
        "resolved_ips": resolve_host_ips(host),
        "errors": [],
    }


def _create_result(normalized_url, host: str, resolved_ips: List[str]) -> Dict[str, Any]:
    """创建基础结果容器。"""
    return {
        "ok": True,
        "url": normalized_url,
        "host": host,
        "resolved_ips": resolved_ips,
        "elapsed_seconds": None,
        "https": False,
        "ssl_valid": False,
        "ssl_days_left": -1,
        "tls": {
            "enabled": None,
            "ok": False,
            "ssl_valid": None,
            "ssl_days_left": None,
            "protocol": "",
            "cipher": {},
            "cipher_weak": None,
            "supported_protocols": [],
            "weak_protocols": [],
            "protocol_probes": [],
            "chain_verified": None,
            "chain_length": None,
            "chain_complete": None,
            "certificate": {},
            "warnings": [],
        },
        "dns_security": {
            "enabled": None,
            "status": "missing",
            "domain": "",
            "lookup_domain": "",
            "spf": {
                "present": None,
                "records": [],
                "policy": None,
            },
            "dmarc": {
                "present": None,
                "records": [],
                "policy": None,
            },
            "caa": {
                "present": None,
                "records": [],
                "issuers": [],
            },
            "findings": [],
            "warnings": [],
        },
        "security_header_score": 0,
        "missing_security_headers": [],
        "trace_enabled": None,
        "http_methods": {
            "enabled": None,
            "options_status": None,
            "allow_methods": [],
            "cors_methods": [],
            "exposed_methods": [],
            "trace_enabled": None,
            "warnings": [],
        },
        "sensitive_paths": [],
        "info_leak": {
            "version_exposed": None,
            "framework_exposed": None,
            "meta_exposed": None,
            "meta_fields": [],
            "header_findings": [],
        },
        "errors": [],
    }


def _request_target(
    session: requests.Session,
    normalized_url: str,
    progress: ScanProgress,
) -> Tuple[requests.Response | None, Dict[str, Any] | None]:
    """请求目标站点并统一处理错误。"""
    progress.update("正在请求目标站点")
    try:
        response = http_request(session, "GET", normalized_url, stream=True, raise_for_status=True)
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "未知"
        return None, {"ok": False, "error": f"目标站点返回异常状态码：{code}"}
    except Exception as e:
        return None, {"ok": False, "error": f"无法访问站点：{e}"}

    progress.update("目标站点请求完成", 1)
    return response, None


def _run_base_checks(
    response: requests.Response,
    scan_options: ScanOptions,
    result: Dict[str, Any],
    progress: ScanProgress,
    session: requests.Session,
    normalized_url: str,
    host: str,
    stop_event=None,
) -> None:
    """执行基础检测项。"""
    check_stop(stop_event)
    result["https"] = check_https(response.url)
    result["https_checked"] = scan_options.check_https
    if scan_options.check_https:
        progress.update("正在检测 HTTPS", 1)

    if scan_options.check_ssl:
        tls_result = inspect_tls_configuration(response.url)
        result["tls"] = {
            "enabled": True,
            **tls_result,
        }
        result["ssl_valid"] = tls_result.get("ssl_valid")
        result["ssl_days_left"] = tls_result.get("ssl_days_left")
        progress.update("正在检测 SSL 证书", 1)
    else:
        result["ssl_valid"] = None
        result["ssl_days_left"] = None
        result["tls"] = {
            "enabled": None,
            "ok": False,
            "ssl_valid": None,
            "ssl_days_left": None,
            "protocol": "",
            "cipher": {},
            "cipher_weak": None,
            "supported_protocols": [],
            "weak_protocols": [],
            "protocol_probes": [],
            "chain_verified": None,
            "chain_length": None,
            "chain_complete": None,
            "certificate": {},
            "warnings": [],
        }

    check_stop(stop_event)
    if scan_options.check_dns_security:
        result["dns_security"] = _detect_dns_security(host, stop_event=stop_event)
        progress.update("正在检测 DNS 安全配置", 1)
    else:
        result["dns_security"] = {
            "enabled": None,
            "status": "missing",
            "domain": "",
            "lookup_domain": "",
            "spf": {"present": None, "records": [], "policy": None},
            "dmarc": {"present": None, "records": [], "policy": None},
            "caa": {"present": None, "records": [], "issuers": []},
            "findings": [],
            "warnings": [],
        }

    check_stop(stop_event)
    headers = response.headers
    if scan_options.check_security_headers:
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        result["missing_security_headers"] = missing
        coverage = (len(SECURITY_HEADERS) - len(missing)) / len(SECURITY_HEADERS)
        result["security_header_score"] = round(coverage * 30)
    else:
        result["missing_security_headers"] = None
        result["security_header_score"] = None
    if scan_options.check_security_headers:
        progress.update("正在检测 HTTP 安全头", 1)

    if scan_options.check_info_leak:
        header_findings, version_exposed, framework_exposed = _detect_header_exposures(headers)
        meta_fields = _detect_meta_fields(response.text or "")
        result["info_leak"]["version_exposed"] = version_exposed
        result["info_leak"]["framework_exposed"] = framework_exposed
        result["info_leak"]["header_findings"] = header_findings
        result["info_leak"]["meta_fields"] = meta_fields
        result["info_leak"]["meta_exposed"] = bool(meta_fields)
    else:
        result["info_leak"]["version_exposed"] = None
        result["info_leak"]["framework_exposed"] = None
        result["info_leak"]["meta_exposed"] = None
        result["info_leak"]["meta_fields"] = []
        result["info_leak"]["header_findings"] = []
    if scan_options.check_info_leak:
        progress.update("正在检测响应头暴露信息", 1)

    if scan_options.check_trace:
        check_stop(stop_event)
        method_info = _detect_http_methods(session, normalized_url, stop_event=stop_event)
        result["http_methods"] = method_info
        result["trace_enabled"] = method_info.get("trace_enabled")
        if method_info.get("warnings"):
            result["errors"].extend(method_info["warnings"])
        progress.update("正在检测 HTTP 方法", 1)
    else:
        result["trace_enabled"] = None
        result["http_methods"] = {
            "enabled": None,
            "options_status": None,
            "allow_methods": [],
            "cors_methods": [],
            "exposed_methods": [],
            "trace_enabled": None,
            "warnings": [],
        }

    if scan_options.check_sensitive_paths:
        found_paths = []
        base = f"{urlparse(normalized_url).scheme}://{urlparse(normalized_url).netloc}"
        for path in SENSITIVE_PATHS:
            check_stop(stop_event)
            test_url = base + path
            try:
                path_response = http_request(session, "GET", test_url, allow_redirects=False)
                if path_response.status_code in (200, 301, 302, 401, 403):
                    found_paths.append(path)
            except Exception as e:
                result["errors"].append(f"敏感路径 {path} 检测异常：{e}")
            progress.update(f"正在检测敏感路径：{path}", 1)
        result["sensitive_paths"] = found_paths
    else:
        result["sensitive_paths"] = None


def _run_page_scan(
    scan_options: ScanOptions,
    normalized_url: str,
    progress: ScanProgress,
    session: requests.Session,
    stop_event=None,
) -> Dict[str, Any] | None:
    """执行页面级扫描。"""
    check_stop(stop_event)
    page_scan = scan_pages(
        session,
        normalized_url,
        scan_options,
        max_pages=scan_options.page_scan_max_pages,
        max_depth=scan_options.page_scan_max_depth,
        progress_callback=progress.page_callback(scan_options),
        stop_event=stop_event,
    )
    progress.complete_page_scan(scan_options)
    return page_scan


def _finalize_result(
    result: Dict[str, Any],
    scan_options: ScanOptions,
    progress: ScanProgress,
    stop_event=None,
) -> Dict[str, Any]:
    """计算评分并补齐汇总字段。"""
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
            "risk_counts": page_scan.get("risk_counts", {"低": 0, "中": 0, "高": 0}),
            "highest_risk": page_scan.get("highest_risk", "无"),
        }
    else:
        result["page_scan_summary"] = {
            "enabled": False,
            "pages_scanned": 0,
            "finding_count": 0,
            "risk_counts": {"低": 0, "中": 0, "高": 0},
            "highest_risk": "无",
        }

    check_stop(stop_event)
    progress.update("检测完成", 1)
    return result


def scan(
    url: str,
    progress_callback=None,
    options: Dict[str, Any] | ScanOptions | None = None,
    stop_event=None,
) -> Dict[str, Any]:
    """执行主站点安全扫描。"""
    timer = Timer()
    context = _create_scan_context(url, progress_callback, options, stop_event)
    if not context.get("ok"):
        context["elapsed_seconds"] = round(timer.elapsed_seconds(), 2)
        return context

    scan_options = context["scan_options"]
    progress = context["progress"]
    session = context["session"]
    normalized_url = context["normalized_url"]
    host = context["host"]
    resolved_ips = context["resolved_ips"]

    result = _create_result(normalized_url, host, resolved_ips)
    response, error = _request_target(session, normalized_url, progress)
    if error is not None:
        error["elapsed_seconds"] = round(timer.elapsed_seconds(), 2)
        return error
    if response is None:
        return {"ok": False, "error": "目标站点请求失败。", "elapsed_seconds": round(timer.elapsed_seconds(), 2)}

    _run_base_checks(response, scan_options, result, progress, session, normalized_url, host, stop_event)

    if scan_options.check_page_scan:
        result["page_scan"] = _run_page_scan(
            scan_options,
            normalized_url,
            progress,
            session,
            stop_event,
        )
    else:
        result["page_scan"] = None

    result["errors"].extend(context["errors"])
    result = _finalize_result(result, scan_options, progress, stop_event)
    result["elapsed_seconds"] = round(timer.elapsed_seconds(), 2)
    return result


def _detect_header_exposures(
    headers: Mapping[str, str],
) -> tuple[list[dict[str, Any]], bool, bool]:
    """识别响应头里的高信号暴露。"""
    findings: list[dict[str, Any]] = []

    server = headers.get("Server", "")
    if server:
        if field_exposes_version(server, SERVER_NAME_RE):
            findings.append(
                {
                    "field": "Server",
                    "risk": "中",
                    "kind": "server_version",
                    "value": server,
                    "message": f"响应头中存在可识别的服务器版本特征：{server}",
                    "suggestion": "尽量隐藏或泛化 Server 头，避免暴露具体服务器版本。",
                }
            )
        elif SERVER_NAME_RE.search(server):
            findings.append(
                {
                    "field": "Server",
                    "risk": "低",
                    "kind": "server_name",
                    "value": server,
                    "message": f"响应头中存在可识别的服务器特征：{server}",
                    "suggestion": "如无必要，尽量减少 Server 头中暴露的服务器信息。",
                }
            )

    x_powered_by = headers.get("X-Powered-By", "")
    if x_powered_by:
        if field_exposes_version(x_powered_by, FRAMEWORK_NAME_RE):
            findings.append(
                {
                    "field": "X-Powered-By",
                    "risk": "中",
                    "kind": "framework_version",
                    "value": x_powered_by,
                    "message": f"响应头中存在可识别的框架版本特征：{x_powered_by}",
                    "suggestion": "移除或收敛 X-Powered-By 头，避免暴露框架版本。",
                }
            )
        elif FRAMEWORK_NAME_RE.search(x_powered_by):
            findings.append(
                {
                    "field": "X-Powered-By",
                    "risk": "低",
                    "kind": "framework_name",
                    "value": x_powered_by,
                    "message": f"响应头中存在可识别的框架特征：{x_powered_by}",
                    "suggestion": "如无必要，避免在响应头中直接暴露框架名称。",
                }
            )

    aspnet_version = headers.get("X-AspNet-Version", "")
    if aspnet_version and VERSION_NUMBER_RE.search(aspnet_version):
        findings.append(
            {
                "field": "X-AspNet-Version",
                "risk": "中",
                "kind": "framework_version",
                "value": aspnet_version,
                "message": f"响应头中存在 ASP.NET 版本特征：{aspnet_version}",
                "suggestion": "关闭或隐藏 ASP.NET 版本信息，减少指纹暴露。",
            }
        )

    aspnet_mvc_version = headers.get("X-AspNetMvc-Version", "")
    if aspnet_mvc_version and VERSION_NUMBER_RE.search(aspnet_mvc_version):
        findings.append(
            {
                "field": "X-AspNetMvc-Version",
                "risk": "中",
                "kind": "framework_version",
                "value": aspnet_mvc_version,
                "message": f"响应头中存在 ASP.NET MVC 版本特征：{aspnet_mvc_version}",
                "suggestion": "关闭或隐藏 ASP.NET MVC 版本信息，减少指纹暴露。",
            }
        )

    generator = headers.get("X-Generator", "")
    if generator and not _is_generic_value(generator):
        findings.append(
            {
                "field": "X-Generator",
                "risk": "低",
                "kind": "generator",
                "value": generator,
                "message": f"响应头中存在生成器特征：{generator}",
                "suggestion": "如无必要，避免在响应头中输出生成器信息。",
            }
        )

    version_exposed = any(item["kind"] == "server_version" or item["kind"] == "framework_version" for item in findings)
    framework_exposed = any(item["kind"] in {"framework_version", "framework_name", "generator"} for item in findings)
    return findings, version_exposed, framework_exposed


def _detect_meta_fields(body: str) -> list[dict[str, Any]]:
    """提取页面源码中的重点 meta 字段。"""
    if not body:
        return []

    soup = BeautifulSoup(body, "html.parser")
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for tag in soup.find_all("meta"):
        if not isinstance(tag, Tag):
            continue

        key_name = _meta_field_name(tag)
        if key_name not in INFO_LEAK_META_KEYS:
            continue

        content = _normalize_meta_value(tag.get("content"))
        if not content or _is_generic_value(content):
            continue

        key = (key_name, content.lower())
        if key in seen:
            continue
        seen.add(key)

        findings.append(
            {
                "field": key_name,
                "risk": "低",
                "value": content,
                "message": f"页面源码中存在重点 meta 字段：{key_name}={content}",
                "suggestion": "检查页面源码中的 meta 信息，避免泄露生成器、站点名或版本信息。",
            }
        )

    return findings


def _detect_http_methods(
    session: requests.Session,
    url: str,
    *,
    stop_event=None,
) -> Dict[str, Any]:
    """检测 HTTP 方法暴露情况。"""
    result: Dict[str, Any] = {
        "enabled": True,
        "options_status": None,
        "allow_methods": [],
        "cors_methods": [],
        "exposed_methods": [],
        "trace_enabled": None,
        "warnings": [],
    }

    check_stop(stop_event)
    try:
        options_resp = http_request(session, "OPTIONS", url, allow_redirects=False)
    except Exception as exc:
        result["warnings"].append(f"HTTP 方法 OPTIONS 检测异常：{exc}")
        options_resp = None

    if options_resp is not None:
        result["options_status"] = options_resp.status_code
        allow_methods = _parse_methods_header(options_resp.headers.get("Allow", ""))
        cors_methods = _parse_methods_header(options_resp.headers.get("Access-Control-Allow-Methods", ""))
        result["allow_methods"] = allow_methods
        result["cors_methods"] = cors_methods
        result["exposed_methods"] = _merge_http_methods(allow_methods, cors_methods)

    check_stop(stop_event)
    try:
        trace_resp = http_request(session, "TRACE", url, allow_redirects=False)
        result["trace_enabled"] = trace_resp.status_code < 400
    except Exception as exc:
        result["warnings"].append(f"TRACE 检测异常：{exc}")
        result["trace_enabled"] = None

    return result


def _parse_methods_header(value: str) -> List[str]:
    """解析 Allow 或 Access-Control-Allow-Methods 头。"""
    methods: List[str] = []
    seen: set[str] = set()
    for raw in re.split(r"[, ]+", value or ""):
        method = raw.strip().upper()
        if not method or method in seen:
            continue
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]*", method):
            continue
        seen.add(method)
        methods.append(method)
    return methods


def _merge_http_methods(*groups: List[str]) -> List[str]:
    """合并多个方法声明并去重。"""
    safe_methods = {"GET", "HEAD", "POST", "OPTIONS", "TRACE"}
    merged: List[str] = []
    seen: set[str] = set()
    for group in groups:
        for method in group or []:
            if method in safe_methods or method in seen:
                continue
            seen.add(method)
            merged.append(method)
    return merged


def _meta_field_name(tag: Tag) -> str:
    """获取 meta 字段名。"""
    for attr in ("name", "property", "itemprop", "http-equiv"):
        value = tag.get(attr)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _normalize_meta_value(value: object) -> str:
    """把 meta content 归一化为普通字符串。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _is_generic_value(value: str) -> bool:
    """判断是否是常见空值或通用值。"""
    normalized = (value or "").strip().lower()
    if not normalized:
        return True
    if normalized in GENERIC_META_VALUES:
        return True
    if len(normalized) <= 2:
        return True
    return False


def _detect_dns_security(host: str, stop_event=None) -> Dict[str, Any]:
    """检测域名的 SPF、DMARC 和 CAA 配置。"""
    result: Dict[str, Any] = {
        "enabled": True,
        "status": "ok",
        "domain": host,
        "lookup_domain": "",
        "spf": {"present": None, "records": [], "policy": None},
        "dmarc": {"present": None, "records": [], "policy": None},
        "caa": {"present": None, "records": [], "issuers": []},
        "findings": [],
        "warnings": [],
    }

    if not host:
        result["status"] = "skipped"
        result["warnings"].append("DNS 安全检测已跳过：未获取到主机名。")
        return result

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        result["status"] = "skipped"
        result["warnings"].append("DNS 安全检测已跳过：当前输入是 IP 地址。")
        return result

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 3.0
    resolver.lifetime = 4.0

    lookup_candidates = _dns_lookup_candidates(host)
    lookup_domain = lookup_candidates[0]
    spf_records: List[str] = []
    dmarc_records: List[str] = []
    caa_records: Dict[str, Any] | None = None
    had_query_error = False

    for candidate in lookup_candidates:
        check_stop(stop_event)
        spf_records, spf_errors = _lookup_txt_records(resolver, candidate)
        dmarc_records, dmarc_errors = _lookup_txt_records(resolver, f"_dmarc.{candidate}")
        caa_records, caa_errors = _lookup_caa_records(resolver, candidate)
        result["warnings"].extend(spf_errors + dmarc_errors + caa_errors)

        if spf_errors or dmarc_errors or caa_errors:
            had_query_error = True

        if spf_records or dmarc_records or (caa_records and caa_records.get("records")):
            lookup_domain = candidate
            break

    result["lookup_domain"] = lookup_domain

    if had_query_error and not (spf_records or dmarc_records or (caa_records and caa_records.get("records"))):
        result["status"] = "error"
        return result

    if spf_records:
        result["spf"]["present"] = True
        result["spf"]["records"] = spf_records
        spf_policy = _classify_spf(spf_records)
        result["spf"]["policy"] = spf_policy["policy"]
        result["findings"].extend(spf_policy["findings"])
    else:
        result["spf"]["present"] = False
        result["findings"].append(
            {
                "risk": "中",
                "type": "SPF 缺失",
                "message": f"未发现 {lookup_domain} 的 SPF 记录。",
                "suggestion": "为域名添加 SPF TXT 记录，限制可代表该域名发信的主机范围。",
            }
        )

    if dmarc_records:
        result["dmarc"]["present"] = True
        result["dmarc"]["records"] = dmarc_records
        dmarc_policy = _classify_dmarc(dmarc_records)
        result["dmarc"]["policy"] = dmarc_policy["policy"]
        result["findings"].extend(dmarc_policy["findings"])
    else:
        result["dmarc"]["present"] = False
        result["findings"].append(
            {
                "risk": "中",
                "type": "DMARC 缺失",
                "message": f"未发现 {lookup_domain} 的 DMARC 记录。",
                "suggestion": "为域名添加 _dmarc TXT 记录，并设置明确的 p 策略。",
            }
        )

    if caa_records and caa_records.get("records"):
        result["caa"]["present"] = True
        result["caa"]["records"] = caa_records.get("records", [])
        result["caa"]["issuers"] = caa_records.get("issuers", [])
        if not caa_records.get("has_issue"):
            result["findings"].append(
                {
                    "risk": "低",
                    "type": "CAA 限制较弱",
                    "message": f"{lookup_domain} 存在 CAA 记录，但未直接限制证书签发 CA。",
                    "suggestion": "如需收紧证书签发范围，可补充 issue 或 issuewild 约束。",
                }
            )
    else:
        result["caa"]["present"] = False
        result["findings"].append(
            {
                "risk": "低",
                "type": "CAA 缺失",
                "message": f"未发现 {lookup_domain} 的 CAA 记录。",
                "suggestion": "为域名添加 CAA 记录，限制允许签发证书的 CA。",
            }
        )

    if not result["findings"]:
        result["findings"].append(
            {
                "risk": "低",
                "type": "DNS 安全配置",
                "message": f"{lookup_domain} 的 SPF、DMARC 和 CAA 均未发现明显问题。",
                "suggestion": "保持当前 DNS 安全配置，并定期核对邮箱和证书策略。",
            }
        )

    return result


def _dns_lookup_candidates(host: str) -> List[str]:
    """生成 DNS 查询候选域名。"""
    normalized = (host or "").strip().rstrip(".").lower()
    candidates: List[str] = []
    if normalized:
        candidates.append(normalized)
        if normalized.startswith("www."):
            stripped = normalized[4:]
            if stripped and stripped not in candidates:
                candidates.append(stripped)
    return candidates


def _lookup_txt_records(
    resolver: dns.resolver.Resolver,
    name: str,
    *,
    stop_event=None,
) -> tuple[List[str], List[str]]:
    """查询 TXT 记录。"""
    check_stop(stop_event)
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], []
    except dns.exception.DNSException as exc:
        return [], [f"DNS 查询 TXT 失败：{name}，{exc}"]

    records: List[str] = []
    for answer in answers:
        text = _dns_record_text(answer)
        if text:
            records.append(text)
    return records, []


def _lookup_caa_records(
    resolver: dns.resolver.Resolver,
    name: str,
    *,
    stop_event=None,
) -> tuple[Dict[str, Any] | None, List[str]]:
    """查询 CAA 记录。"""
    check_stop(stop_event)
    try:
        answers = resolver.resolve(name, "CAA")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None, []
    except dns.exception.DNSException as exc:
        return None, [f"DNS 查询 CAA 失败：{name}，{exc}"]

    records: List[str] = []
    issuers: List[str] = []
    has_issue = False
    for answer in answers:
        text = _dns_record_text(answer)
        if text:
            records.append(text)
        parsed = _parse_caa_text(text)
        if parsed is None:
            continue
        tag, value = parsed
        if tag in {"issue", "issuewild"}:
            has_issue = True
            if value:
                issuers.append(value)

    return {"records": records, "issuers": issuers, "has_issue": has_issue}, []


def _dns_record_text(record: Any) -> str:
    """把 DNS 记录转成可读文本。"""
    text = getattr(record, "to_text", None)
    if callable(text):
        return str(text()).strip().strip('"')

    strings = getattr(record, "strings", None)
    if strings:
        parts: list[str] = []
        for part in strings:
            if isinstance(part, bytes):
                parts.append(part.decode("utf-8", "ignore"))
            else:
                parts.append(str(part))
        return "".join(parts).strip()

    return str(record).strip()


def _parse_caa_text(text: str) -> tuple[str, str] | None:
    """解析 CAA 文本记录。"""
    candidate = (text or "").strip()
    if not candidate:
        return None

    parts = candidate.split(None, 2)
    if len(parts) < 2:
        return None

    tag = parts[1].lower()
    value = parts[2].strip().strip('"') if len(parts) > 2 else ""
    return tag, value


def _classify_spf(records: List[str]) -> Dict[str, Any]:
    """分析 SPF 记录的收紧程度。"""
    findings: List[Dict[str, Any]] = []
    record = next((item for item in records if "v=spf1" in item.lower()), "")
    policy = "unknown"

    if not record:
        findings.append(
            {
                "risk": "中",
                "type": "SPF 记录无效",
                "message": "TXT 记录中未发现有效的 SPF 策略。",
                "suggestion": "确认 SPF 记录是否正确发布，且内容以 v=spf1 开头。",
            }
        )
        return {"policy": policy, "findings": findings}

    tokens = record.split()
    all_token = next((token.lower() for token in tokens if token.lower().endswith("all")), "")
    if all_token in {"+all", "all"}:
        policy = "open"
        findings.append(
            {
                "risk": "高",
                "type": "SPF 过宽",
                "message": f"SPF 记录允许几乎任意主机代表域名发信：{record}",
                "suggestion": "将 SPF 收紧为明确的发送主机，并使用 -all 结束策略。",
            }
        )
    elif all_token == "~all":
        policy = "softfail"
        findings.append(
            {
                "risk": "低",
                "type": "SPF 策略偏宽",
                "message": f"SPF 记录使用软失败策略：{record}",
                "suggestion": "如条件允许，可进一步收紧为 -all。",
            }
        )
    elif all_token == "-all":
        policy = "strict"
    else:
        policy = "unknown"
        findings.append(
            {
                "risk": "中",
                "type": "SPF 结束策略不明确",
                "message": f"SPF 记录未看到明确的 -all 结束策略：{record}",
                "suggestion": "建议使用 -all 收尾，明确拒绝未授权的发信来源。",
            }
        )

    return {"policy": policy, "findings": findings}


def _classify_dmarc(records: List[str]) -> Dict[str, Any]:
    """分析 DMARC 策略。"""
    findings: List[Dict[str, Any]] = []
    record = next((item for item in records if "v=dmarc1" in item.lower()), "")
    policy = "unknown"

    if not record:
        findings.append(
            {
                "risk": "中",
                "type": "DMARC 记录无效",
                "message": "TXT 记录中未发现有效的 DMARC 策略。",
                "suggestion": "确认 _dmarc 子域已正确发布 DMARC 记录。",
            }
        )
        return {"policy": policy, "findings": findings}

    match = re.search(r"(?i)(?:^|;)\s*p\s*=\s*([a-z]+)", record)
    dmarc_policy = (match.group(1).lower() if match else "")
    if dmarc_policy == "reject":
        policy = "reject"
    elif dmarc_policy == "quarantine":
        policy = "quarantine"
        findings.append(
            {
                "risk": "低",
                "type": "DMARC 仍偏宽",
                "message": f"DMARC 策略为 quarantine：{record}",
                "suggestion": "如条件允许，可进一步收紧为 p=reject。",
            }
        )
    elif dmarc_policy == "none":
        policy = "none"
        findings.append(
            {
                "risk": "中",
                "type": "DMARC 仅监控",
                "message": f"DMARC 策略为 none：{record}",
                "suggestion": "建议尽快提升为 quarantine 或 reject，以降低仿冒邮件风险。",
            }
        )
    else:
        findings.append(
            {
                "risk": "中",
                "type": "DMARC 策略不明确",
                "message": f"DMARC 记录中未看到明确的 p 策略：{record}",
                "suggestion": "为 DMARC 增加明确的 p=reject 或 p=quarantine。",
            }
        )

    return {"policy": policy, "findings": findings}

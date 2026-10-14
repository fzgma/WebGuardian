"""基础站点检查：HTTPS、安全头、暴露信息、HTTP 方法和敏感路径。"""

import re
from collections.abc import Mapping
from threading import Event
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from bs4.element import Tag
import requests

from utils.control import check_stop
from utils.net import http_request
from result_model.composer import wrap_section_result
from result_model.models import ScanContext, SectionResult, SectionStatus
from .header_rules import SECURITY_HEADERS as SECURITY_HEADERS, assess_security_headers

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
    "/docs",
]
SERVER_NAME_RE = re.compile(r"(?i)\b(?:apache|nginx|iis|openresty|tomcat)\b")
FRAMEWORK_NAME_RE = re.compile(
    r"(?i)\b(?:php|asp\.net|express|django|spring|laravel|rails|koa|fastapi|flask)\b"
)
VERSION_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")


def run_base_checks(context: ScanContext, response: requests.Response) -> dict[str, SectionResult]:
    """执行基础站点检查并返回各 section。"""
    options = context.scan_options
    session = context.session
    normalized_url = context.normalized_url
    stop_event = context.stop_event
    progress = context.progress
    checks: dict[str, SectionResult] = {}

    check_stop(stop_event)
    https_value = check_https(response.url)
    checks["https"] = wrap_section_result(
        "https",
        {"value": https_value, "meta": {"assessment": "complete"}},
        enabled=options.check_https,
        status=SectionStatus.OK if options.check_https else SectionStatus.DISABLED,
        summary="最终访问地址使用 HTTPS。" if https_value else "最终访问地址未使用 HTTPS。",
    )
    if options.check_https:
        progress.update("正在检测 HTTPS", 1)

    headers = response.headers
    if options.check_security_headers:
        header_result = assess_security_headers(headers)
        checks["security_headers"] = wrap_section_result(
            "security_headers",
            header_result,
            enabled=True,
            status=SectionStatus.WARN if header_result["missing"] or header_result["invalid"] else SectionStatus.OK,
            summary="HTTP 安全响应头的存在性与基础语义检查完成。",
        )
        progress.update("正在检测 HTTP 安全头", 1)
    else:
        checks["security_headers"] = wrap_section_result(
            "security_headers",
            {"score": None, "missing": [], "invalid": [], "coverage": None},
            enabled=False,
            status=SectionStatus.DISABLED,
            summary="HTTP 安全响应头检测已关闭。",
        )

    if options.check_info_leak:
        header_findings, version_exposed, framework_exposed = _detect_header_exposures(headers)
        meta_fields = _detect_meta_fields(response.text or "")
        checks["info_leak"] = wrap_section_result(
            "info_leak",
            {
                "version_exposed": version_exposed,
                "framework_exposed": framework_exposed,
                "meta_exposed": bool(meta_fields),
                "meta_fields": meta_fields,
                "header_findings": header_findings,
                "meta": {"assessment": "complete"},
            },
            enabled=True,
            status=SectionStatus.OK,
            summary="暴露信息检测完成。",
            findings=header_findings + meta_fields,
        )
        progress.update("正在检测响应头暴露信息", 1)
    else:
        checks["info_leak"] = wrap_section_result(
            "info_leak",
            {
                "version_exposed": None,
                "framework_exposed": None,
                "meta_exposed": None,
                "meta_fields": [],
                "header_findings": [],
            },
            enabled=False,
            status=SectionStatus.DISABLED,
            summary="暴露信息检测已关闭。",
        )

    if options.check_trace:
        check_stop(stop_event)
        method_info = _detect_http_methods(session, normalized_url, stop_event=stop_event)
        checks["http_methods"] = wrap_section_result(
            "http_methods",
            method_info,
            enabled=True,
            status=(
                SectionStatus.ERROR if method_info["meta"]["assessment"] == "unknown"
                else SectionStatus.WARN if method_info.get("warnings")
                else SectionStatus.OK
            ),
            summary="HTTP 方法检测完成。",
            warnings=method_info.get("warnings", []),
        )
        progress.update("正在检测 HTTP 方法", 1)
    else:
        checks["http_methods"] = wrap_section_result(
            "http_methods",
            {
                "options_status": None,
                "allow_methods": [],
                "cors_methods": [],
                "exposed_methods": [],
                "trace_enabled": None,
                "warnings": [],
            },
            enabled=False,
            status=SectionStatus.DISABLED,
            summary="HTTP 方法检测已关闭。",
        )

    if options.check_sensitive_paths:
        path_result = _detect_sensitive_paths(context)
        assessment = path_result["meta"]["assessment"]
        checks["sensitive_paths"] = wrap_section_result(
            "sensitive_paths",
            path_result,
            enabled=True,
            status=(
                SectionStatus.ERROR if assessment == "unknown"
                else SectionStatus.WARN if assessment == "partial" or path_result["paths"]
                else SectionStatus.OK
            ),
            summary="敏感路径响应检查完成；疑似可访问的路径不等于已确认漏洞。",
        )
    else:
        checks["sensitive_paths"] = wrap_section_result(
            "sensitive_paths",
            {"paths": []},
            enabled=False,
            status=SectionStatus.DISABLED,
            summary="敏感路径检测已关闭。",
        )

    return checks


def _detect_sensitive_paths(context: ScanContext) -> dict[str, Any]:
    """保留每个有限路径探测的证据，区分未发现与未能判断。"""
    parsed_url = urlparse(context.normalized_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    observations: list[dict[str, Any]] = []
    paths: list[str] = []
    warnings: list[str] = []
    failed_count = 0
    inconclusive_count = 0
    for path in SENSITIVE_PATHS:
        check_stop(context.stop_event)
        observation: dict[str, Any] = {"path": path, "status_code": None}
        try:
            response = http_request(context.session, "GET", base_url + path, allow_redirects=False)
            code = response.status_code
            observation["status_code"] = code
            if code in {401, 403}:
                observation.update(status="protected", reason="访问被拒绝或要求认证，未确认公开暴露。")
            elif code in {404, 410}:
                observation.update(status="not_found", reason="服务器返回资源不存在。")
            elif 300 <= code < 400:
                observation.update(status="redirect", reason="路径返回跳转，未跟进落地点，不能据此确认暴露。")
                inconclusive_count += 1
                warnings.append(f"敏感路径 {path} 返回 HTTP {code} 跳转，未验证跳转后的内容。")
            elif 200 <= code < 300:
                observation.update(
                    status="suspected_exposure",
                    reason="路径响应成功，疑似可访问；尚未排除 soft-404 或统一登录页，不代表已确认漏洞。",
                )
                paths.append(path)
            else:
                observation.update(status="error", reason=f"HTTP {code} 无法可靠判断路径是否公开。")
        except requests.RequestException as exc:
            observation.update(status="error", reason=f"请求失败：{type(exc).__name__}")
        if observation["status"] == "error":
            failed_count += 1
            inconclusive_count += 1
            warnings.append(f"敏感路径 {path} 检测未完成：{observation['reason']}")
        observations.append(observation)
        context.progress.update(f"正在检测敏感路径：{path}", 1)

    conclusive_count = len(observations) - inconclusive_count
    assessment = "complete" if not inconclusive_count else "partial" if conclusive_count else "unknown"
    return {
        "paths": paths,
        "checked_count": len(observations) - failed_count,
        "failed_count": failed_count,
        "total_count": len(observations),
        "observations": observations,
        "warnings": warnings,
        "meta": {"assessment": assessment},
    }


def check_https(url: str) -> bool:
    """判断最终地址是否走 HTTPS。"""
    return url.startswith("https://")


def field_exposes_version(value: str, name_re: re.Pattern[str]) -> bool:
    """判断文本是否同时包含技术栈名称和版本号。"""
    return bool(value and name_re.search(value) and VERSION_NUMBER_RE.search(value))


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

    version_exposed = any(
        item["kind"] in {"server_version", "framework_version"} for item in findings
    )
    framework_exposed = any(
        item["kind"] in {"framework_version", "framework_name", "generator"}
        for item in findings
    )
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
    stop_event: Event | None = None,
) -> Dict[str, Any]:
    """检测 HTTP 方法暴露情况。"""
    result: Dict[str, Any] = {
        "enabled": True,
        "options_status": None,
        "allow_methods": [],
        "cors_methods": [],
        "exposed_methods": [],
        "trace_enabled": None,
        "trace_status": None,
        "trace_evidence": "",
        "options_assessment": "unknown",
        "warnings": [],
    }

    check_stop(stop_event)
    try:
        options_resp = http_request(session, "OPTIONS", url, allow_redirects=False)
    except requests.RequestException as exc:
        result["warnings"].append(f"HTTP 方法 OPTIONS 检测异常：{exc}")
        options_resp = None

    if options_resp is not None:
        result["options_status"] = options_resp.status_code
        allow_methods = _parse_methods_header(options_resp.headers.get("Allow", ""))
        cors_methods = _parse_methods_header(
            options_resp.headers.get("Access-Control-Allow-Methods", "")
        )
        result["allow_methods"] = allow_methods
        result["cors_methods"] = cors_methods
        result["exposed_methods"] = _merge_http_methods(allow_methods, cors_methods)
        if (200 <= options_resp.status_code < 300 or options_resp.status_code == 405) and (allow_methods or cors_methods):
            result["options_assessment"] = "complete"
        else:
            result["warnings"].append("OPTIONS 未提供可用于判断方法声明的有效响应，空列表不表示已禁用其他方法。")

    check_stop(stop_event)
    try:
        trace_resp = http_request(session, "TRACE", url, allow_redirects=False)
        result["trace_status"] = trace_resp.status_code
        if trace_resp.status_code in {405, 501}:
            result["trace_enabled"] = False
            result["trace_evidence"] = f"服务器以 HTTP {trace_resp.status_code} 明确拒绝 TRACE 方法。"
        elif 200 <= trace_resp.status_code < 300 and re.match(
            r"^TRACE\s+\S+\s+HTTP/\d(?:\.\d)?(?:\r?\n|$)",
            getattr(trace_resp, "text", "") or "",
        ):
            result["trace_enabled"] = True
            result["trace_evidence"] = "成功响应中回显了 TRACE 请求行。"
        else:
            result["trace_evidence"] = f"HTTP {trace_resp.status_code} 未提供明确的 TRACE 回显或禁用证据。"
            result["warnings"].append(result["trace_evidence"])
    except requests.RequestException as exc:
        result["warnings"].append(f"TRACE 检测异常：{exc}")
        result["trace_enabled"] = None

    known_probes = int(result["options_assessment"] == "complete") + int(result["trace_enabled"] is not None)
    result["meta"] = {"assessment": "complete" if known_probes == 2 else "partial" if known_probes else "unknown"}
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
    return not normalized or normalized in GENERIC_META_VALUES or len(normalized) <= 2

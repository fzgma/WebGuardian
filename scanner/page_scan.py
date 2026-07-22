from collections import deque
from html.parser import HTMLParser
import re
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from .net import http_request
from .options import ScanOptions


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        """解析页面中的链接、资源和表单。"""
        super().__init__()
        self.links: List[str] = []
        self.resources: List[str] = []
        self.forms: List[Dict[str, str]] = []
        self.text_chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """收集页面标签里的目标属性。"""
        attr_map = {name.lower(): (value or "") for name, value in attrs}
        tag = tag.lower()
        if tag == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"])
        elif tag in {"img", "script", "iframe", "source"} and attr_map.get("src"):
            self.resources.append(attr_map["src"])
        elif tag == "link" and attr_map.get("href"):
            self.resources.append(attr_map["href"])
        elif tag == "form":
            self.forms.append(
                {
                    "action": attr_map.get("action", ""),
                    "method": attr_map.get("method", "get").lower(),
                }
            )

    def handle_data(self, data: str) -> None:
        """保存页面文本片段。"""
        if data and data.strip():
            self.text_chunks.append(data.strip())


def _same_origin(base_url: str, candidate_url: str) -> bool:
    """判断两个地址是否同源。"""
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return (base.scheme, base.netloc) == (candidate.scheme, candidate.netloc)


def _is_html(content_type: str) -> bool:
    """判断响应是否为 HTML 页面。"""
    lowered = content_type.lower()
    return "text/html" in lowered or "application/xhtml+xml" in lowered


def _append_finding(
    findings: List[Dict[str, Any]],
    *,
    risk: str,
    finding_type: str,
    url: str,
    message: str,
    suggestion: str,
) -> None:
    """追加一条页面级发现。"""
    findings.append(
        {
            "url": url,
            "risk": risk,
            "type": finding_type,
            "message": message,
            "suggestion": suggestion,
        }
    )


def _cookie_flag_state(response: requests.Response) -> Dict[str, bool]:
    """提取 Cookie 安全属性状态。"""
    flags = {"secure": False, "httponly": False, "samesite": False}
    for cookie in response.cookies:
        if cookie.secure:
            flags["secure"] = True
        rest = getattr(cookie, "_rest", {}) or {}
        for key in rest:
            lowered = key.lower()
            if lowered == "httponly":
                flags["httponly"] = True
            elif lowered == "samesite":
                flags["samesite"] = True
    return flags


def _extract_redirect_chain(response: requests.Response, start_url: str) -> List[Dict[str, Any]]:
    """整理重定向链。"""
    chain: List[Dict[str, Any]] = []
    previous_url = start_url
    for hop in list(response.history) + [response]:
        chain.append(
            {
                "from": previous_url,
                "to": hop.url,
                "status_code": hop.status_code,
            }
        )
        previous_url = hop.url
    return chain


EXPOSED_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b"),
        "loopback address",
        "页面源码中出现本机回环地址，可能暴露本地联调信息。",
    ),
    (
        re.compile(r"(?i)\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "private ip 10.x",
        "页面源码中出现 10.x 私网地址，可能暴露内网拓扑。",
    ),
    (
        re.compile(r"(?i)\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        "private ip 192.168.x.x",
        "页面源码中出现 192.168 私网地址，可能暴露内网拓扑。",
    ),
    (
        re.compile(r"(?i)\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b"),
        "private ip 172.16-31.x.x",
        "页面源码中出现 172.16-31 私网地址，可能暴露内网拓扑。",
    ),
    (
        re.compile(r"(?i)(?:^|[\"'=\s/])(debug|test|staging|stage|preprod)(?:[./_-]|$)"),
        "environment marker",
        "页面源码中出现环境标识路径或子域，可能暴露测试或预发环境。",
    ),
    (
        re.compile(r"(?i)(?:NODE_ENV\s*=\s*development|__DEV__|debug\s*=\s*true)"),
        "debug flag",
        "页面源码中出现调试开关或开发环境标识。",
    ),
    (
        re.compile(r"(?i)(?:sourceMappingURL=|\.map\b|webpack://)"),
        "source map",
        "页面源码中出现 source map 或调试构建痕迹，可能帮助还原前端源码。",
    ),
    (
        re.compile(r"(?i)\b(?:swagger|openapi|graphql|graphiql|playground|api-docs)\b"),
        "api explorer",
        "页面源码中出现接口文档或调试入口，可能扩大攻击面。",
    ),
] 


def _detect_exposed_info(body: str) -> Tuple[List[str], str]:
    """识别页面源码里的高信号暴露信息。"""
    matched_patterns: List[str] = []
    risk = "低"
    medium_signals = {
        "loopback address",
        "private ip 10.x",
        "private ip 192.168.x.x",
        "private ip 172.16-31.x.x",
    }
    low_signals = {
        "environment marker",
        "debug flag",
        "source map",
        "api explorer",
    }

    for regex, label, description in EXPOSED_PATTERNS:
        if regex.search(body):
            matched_patterns.append(f"{label}: {description}")
            if label in medium_signals:
                risk = "中"
            elif label in low_signals and risk != "中":
                risk = "低"

    return matched_patterns, risk


def scan_pages(
    session: requests.Session,
    start_url: str,
    options: ScanOptions,
    *,
    max_pages: int = 10,
    max_depth: int = 2,
    progress_callback=None,
) -> Dict[str, Any]:
    """执行同源页面级安全检查。"""
    findings: List[Dict[str, Any]] = []
    visited: Set[str] = set()
    queue: Deque[Tuple[str, int]] = deque([(start_url, 0)])
    pages_scanned = 0
    risk_counts = {"低": 0, "中": 0, "高": 0}
    highest_risk = "低"
    page_findings = 0
    scanned_urls: List[str] = []
    redirect_issues: List[Dict[str, Any]] = []
    redirect_chains: List[Dict[str, Any]] = []
    warnings: List[str] = []

    last_progress_percent = -1
    last_progress_text = ""

    def update_progress(percent: int, text: str) -> None:
        """向外汇报页面扫描进度。"""
        if progress_callback:
            nonlocal last_progress_percent, last_progress_text
            if percent == last_progress_percent and text == last_progress_text:
                return
            last_progress_percent = percent
            last_progress_text = text
            progress_callback(percent, text)

    def bump_risk(level: str) -> None:
        """更新当前最高风险等级。"""
        nonlocal highest_risk
        if level in risk_counts:
            risk_counts[level] += 1
        order = {"低": 0, "中": 1, "高": 2}
        if level in order and order[level] > order[highest_risk]:
            highest_risk = level

    def add_finding(
        risk: str,
        finding_type: str,
        url: str,
        message: str,
        suggestion: str,
    ) -> None:
        """记录一条页面发现并累计风险。"""
        nonlocal page_findings
        _append_finding(
            findings,
            risk=risk,
            finding_type=finding_type,
            url=url,
            message=message,
            suggestion=suggestion,
        )
        page_findings += 1
        bump_risk(risk)

    subchecks = [
        ("check_page_redirects", "页面重定向", "检测是否从 HTTPS 跳到 HTTP，或跳转到其他源。"),
        ("check_page_headers", "页面安全头", "检查重点页面是否缺少 CSP、HSTS 等响应头。"),
        ("check_page_cookie_flags", "Cookie 安全属性", "检查 Cookie 是否包含 Secure、HttpOnly、SameSite。"),
        ("check_page_mixed_content", "混合内容", "检查 HTTPS 页面是否加载 HTTP 资源。"),
        ("check_page_forms", "不安全表单", "检查 form action 是否指向 HTTP。"),
        ("check_page_exposed_info", "暴露性信息", "检查页面源码是否暴露内网地址、测试路径或调试信息。"),
    ]
    enabled_subchecks = [item for item in subchecks if getattr(options, item[0], False)]

    if not enabled_subchecks:
        warnings.append("页面级扫描已启用，但未选择具体检查项。")
        return {
            "enabled": True,
            "pages_scanned": 0,
            "max_pages": max_pages,
            "max_depth": max_depth,
            "finding_count": 0,
            "page_findings": 0,
            "highest_risk": "低",
            "findings": [],
            "risk_counts": risk_counts,
            "visited_urls": [],
            "redirect_issues": [],
            "redirect_chains": [],
            "warnings": warnings,
            "message": "页面级扫描已启用，但未选择具体检查项。",
        }

    update_progress(68, "正在准备页面级安全检查")

    while queue and pages_scanned < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue

        visited.add(current_url)
        scanned_urls.append(current_url)
        pages_scanned += 1
        update_progress(
            70 + min(20, int((pages_scanned / max_pages) * 20)),
            f"正在分析页面 {pages_scanned}/{max_pages}",
        )

        try:
            response = http_request(session, "GET", current_url, allow_redirects=True)
        except Exception as exc:
            add_finding(
                "中",
                "request_error",
                current_url,
                f"页面请求失败：{exc}",
                "确认页面是否可访问，或降低扫描深度后重试。",
            )
            continue

        redirect_chain = _extract_redirect_chain(response, current_url)
        if len(redirect_chain) > 1:
            redirect_chains.append(
                {
                    "url": current_url,
                    "chain": redirect_chain,
                }
            )

        final_url = response.url
        if options.check_page_redirects and response.history:
            for hop in response.history:
                previous = current_url
                request_obj = getattr(hop, "request", None)
                if request_obj is not None:
                    previous = getattr(request_obj, "url", "") or current_url
                current = hop.url
                redirect_issues.append(
                    {
                        "from": previous,
                        "to": current,
                        "status_code": hop.status_code,
                    }
                )
                if previous.startswith("https://") and current.startswith("http://"):
                    add_finding(
                        "高",
                        "downgrade_redirect",
                        previous,
                        "页面重定向链中出现从 HTTPS 到 HTTP 的降级跳转。",
                        "移除会降级协议的跳转，确保 HTTPS 请求不会被导向 HTTP 页面。",
                    )
                if not _same_origin(start_url, current):
                    add_finding(
                        "高",
                        "cross_origin_redirect",
                        previous,
                        "页面发生了跨源跳转。",
                        "检查跳转目标是否为可信域名，避免将用户导向第三方站点。",
                    )

        if options.check_page_redirects and not _same_origin(start_url, final_url):
            add_finding(
                "高",
                "cross_origin_redirect",
                current_url,
                "页面发生了跨源跳转。",
                "检查跳转目标是否为可信域名，避免将用户导向第三方站点。",
            )
            continue

        content_type = response.headers.get("Content-Type", "")
        if not _is_html(content_type):
            continue

        parser = _PageParser()
        body = response.text or ""
        parser.feed(body)
        base_url = response.url

        if options.check_page_cookie_flags:
            update_progress(
                70 + 6,
                f"页面 {pages_scanned}/{max_pages}：Cookie 安全属性",
            )
            flags = _cookie_flag_state(response)
            if not all(flags.values()):
                add_finding(
                    "中",
                    "cookie_flags",
                    base_url,
                    (
                        "Cookie 安全属性不完整："
                        f"Secure={flags['secure']}, "
                        f"HttpOnly={flags['httponly']}, "
                        f"SameSite={flags['samesite']}"
                    ),
                    "为敏感 Cookie 启用 Secure、HttpOnly 和 SameSite。",
                )

        if options.check_page_headers:
            update_progress(
                70 + 8,
                f"页面 {pages_scanned}/{max_pages}：页面安全头",
            )
            header_names = {name.lower() for name in response.headers.keys()}
            missing_headers = []
            for required in ("content-security-policy", "strict-transport-security"):
                if required not in header_names:
                    missing_headers.append(required.upper())
            if missing_headers:
                add_finding(
                    "中",
                    "missing_headers",
                    base_url,
                    f"页面缺少安全响应头：{', '.join(missing_headers)}",
                    "为重点页面补充 CSP 和 HSTS 等安全头。",
                )

        if options.check_page_mixed_content and base_url.startswith("https://"):
            update_progress(
                70 + 10,
                f"页面 {pages_scanned}/{max_pages}：混合内容",
            )
            for resource_url in parser.resources:
                absolute = urljoin(base_url, resource_url)
                if absolute.startswith("http://"):
                    add_finding(
                        "高",
                        "mixed_content",
                        base_url,
                        f"发现不安全资源：{absolute}",
                        "将页面资源统一切换为 HTTPS，避免混合内容。",
                    )

        if options.check_page_forms and base_url.startswith("https://"):
            update_progress(
                70 + 12,
                f"页面 {pages_scanned}/{max_pages}：不安全表单",
            )
            for form in parser.forms:
                action = form.get("action", "").strip()
                if not action:
                    continue
                absolute_action = urljoin(base_url, action)
                if absolute_action.startswith("http://"):
                    add_finding(
                        "高",
                        "insecure_form",
                        base_url,
                        f"表单提交地址使用了不安全协议：{absolute_action}",
                        "将表单 action 修改为 HTTPS 地址。",
                    )

        if options.check_page_exposed_info:
            update_progress(
                70 + 14,
                f"页面 {pages_scanned}/{max_pages}：暴露信息",
            )
            matched_patterns, risk = _detect_exposed_info(body)
            if matched_patterns:
                add_finding(
                    risk,
                    "exposed_info",
                    base_url,
                    "页面源码中发现可疑暴露信息：" + "；".join(matched_patterns),
                    "检查页面源码、前端配置与构建产物，移除测试地址、调试标记和内网引用。",
                )

        # 只继续抓取同源 HTML 链接，避免扩成爬虫。
        for link in parser.links:
            absolute_link = urljoin(base_url, link)
            if _same_origin(start_url, absolute_link):
                parsed_link = urlparse(absolute_link)
                if parsed_link.scheme in {"http", "https"}:
                    queue.append((absolute_link, depth + 1))

    return {
        "enabled": True,
        "pages_scanned": pages_scanned,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "finding_count": len(findings),
        "page_findings": page_findings,
        "highest_risk": highest_risk,
        "findings": findings,
        "risk_counts": risk_counts,
        "visited_urls": scanned_urls,
        "redirect_issues": redirect_issues,
        "redirect_chains": redirect_chains,
        "warnings": warnings,
        "message": None,
    }

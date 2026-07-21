"""页面级安全检查规则。"""

from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests


class PageParser(HTMLParser):
    """解析页面中的链接、资源和表单。"""

    def __init__(self) -> None:
        """初始化页面解析结果。"""
        super().__init__()
        self.links: List[str] = []
        self.resources: List[str] = []
        self.forms: List[Dict[str, str]] = []

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


def is_same_origin(base_url: str, candidate_url: str) -> bool:
    """判断两个地址是否同源。"""
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return (base.scheme, base.netloc) == (candidate.scheme, candidate.netloc)


def is_same_host(base_url: str, candidate_url: str) -> bool:
    """判断两个地址是否属于同一个站点。"""
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return bool(
        base.hostname
        and candidate.hostname
        and _normalize_site_host(base.hostname) == _normalize_site_host(candidate.hostname)
    )


def _normalize_site_host(host: str) -> str:
    """归一化常见的站点别名主机。"""
    normalized = host.rstrip(".").lower()
    if normalized.startswith("www."):
        return normalized[4:]
    return normalized


def is_html(content_type: str) -> bool:
    """判断响应是否为 HTML 页面。"""
    lowered = content_type.lower()
    return "text/html" in lowered or "application/xhtml+xml" in lowered


def cookie_flag_state(response: requests.Response) -> Dict[str, bool]:
    """提取 Cookie 安全属性状态。"""
    flags = {"secure": False, "httponly": False, "samesite": False}
    for cookie in response.cookies:
        if cookie.secure:
            flags["secure"] = True
        for key in getattr(cookie, "_rest", {}) or {}:
            lowered = key.lower()
            if lowered == "httponly":
                flags["httponly"] = True
            elif lowered == "samesite":
                flags["samesite"] = True
    return flags


def extract_redirect_chain(
    response: requests.Response, start_url: str
) -> List[Dict[str, Any]]:
    """整理重定向链。"""
    chain: List[Dict[str, Any]] = []
    for hop in response.history:
        source_url = getattr(getattr(hop, "request", None), "url", "") or start_url
        location = hop.headers.get("Location", "")
        target_url = urljoin(source_url, location) if location else hop.url
        chain.append({"from": source_url, "to": target_url, "status_code": hop.status_code})
    return chain


EXPOSED_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b"), "loopback address", "页面源码中出现本机回环地址，可能暴露本地联调信息。"),
    (re.compile(r"(?i)\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "private ip 10.x", "页面源码中出现 10.x 私网地址，可能暴露内网拓扑。"),
    (re.compile(r"(?i)\b192\.168\.\d{1,3}\.\d{1,3}\b"), "private ip 192.168.x.x", "页面源码中出现 192.168 私网地址，可能暴露内网拓扑。"),
    (re.compile(r"(?i)\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b"), "private ip 172.16-31.x.x", "页面源码中出现 172.16-31 私网地址，可能暴露内网拓扑。"),
    (re.compile(r"(?i)(?:^|[\"'=\s/])(debug|test|staging|stage|preprod)(?:[./_-]|$)"), "environment marker", "页面源码中出现环境标识路径或子域，可能暴露测试或预发环境。"),
    (re.compile(r"(?i)(?:NODE_ENV\s*=\s*development|__DEV__|debug\s*=\s*true)"), "debug flag", "页面源码中出现调试开关或开发环境标识。"),
    (re.compile(r"(?i)(?:sourceMappingURL=|\.map\b|webpack://)"), "source map", "页面源码中出现 source map 或调试构建痕迹，可能帮助还原前端源码。"),
    (re.compile(r"(?i)\b(?:swagger|openapi|graphql|graphiql|playground|api-docs)\b"), "api explorer", "页面源码中出现接口文档或调试入口，可能扩大攻击面。"),
]


def detect_exposed_info(body: str) -> Tuple[List[str], str]:
    """识别页面源码里的高信号暴露信息。"""
    matched_patterns: List[str] = []
    risk = "低"
    medium_signals = {
        "loopback address", "private ip 10.x", "private ip 192.168.x.x", "private ip 172.16-31.x.x"
    }
    for regex, label, description in EXPOSED_PATTERNS:
        if regex.search(body):
            matched_patterns.append(f"{label}: {description}")
            if label in medium_signals:
                risk = "中"
    return matched_patterns, risk


def resolve_links(base_url: str, links: List[str]) -> List[str]:
    """筛选同源 HTTP 链接。"""
    resolved = []
    for link in links:
        absolute_link = urljoin(base_url, link)
        if is_same_origin(base_url, absolute_link) and urlparse(absolute_link).scheme in {"http", "https"}:
            resolved.append(absolute_link)
    return resolved

"""robots.txt 站点公开策略分析。"""


import re
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List

import requests

from utils.control import check_stop
from utils.net import http_request

_POLICY_PATTERNS: list[tuple[re.Pattern[str], str, str, str, str]] = [
    (
        re.compile(
            r"(?i)(?:^|/)(?:\.env|\.git(?:/HEAD)?|web\.config|phpinfo\.php|server-status|docker-compose\.ya?ml|backup\.zip|db\.sql|config\.json)(?:$|/)"
        ),
        "高",
        "文件泄露",
        "robots.txt 中出现高信号文件路径：{path}",
        "确认该路径是否应被公开引用，必要时移除或加强访问控制。",
    ),
    (
        re.compile(r"(?i)(?:^|/)(?:admin|manage|backend|console|control|portal)(?:[./_-]|$)"),
        "高",
        "管理入口",
        "robots.txt 中出现管理入口路径：{path}",
        "确认管理入口是否应对外暴露，必要时限制访问来源或加入认证。",
    ),
    (
        re.compile(r"(?i)(?:^|/)(?:backup|bak|archive|dump|sql|database)(?:[./_-]|$)"),
        "高",
        "备份或数据库痕迹",
        "robots.txt 中出现备份或数据库相关路径：{path}",
        "确认是否残留备份、导出或数据库文件，并及时收敛公开入口。",
    ),
    (
        re.compile(r"(?i)(?:^|/)(?:swagger|openapi|api-docs|redoc|graphql|actuator)(?:[./_-]|$)"),
        "中",
        "接口文档或管理端点",
        "robots.txt 中出现接口文档或管理端点：{path}",
        "确认文档和管理端点是否需要公开，避免不必要地扩大攻击面。",
    ),
    (
        re.compile(r"(?i)(?:^|/)(?:debug|diagnostics|metrics|monitor|logs|trace)(?:[./_-]|$)"),
        "中",
        "调试或诊断入口",
        "robots.txt 中出现调试或诊断相关路径：{path}",
        "确认调试、监控和日志入口是否需要对外开放。",
    ),
]


def scan_crawl_policy(
    session: requests.Session,
    start_url: str,
    *,
    stop_event=None,
) -> Dict[str, Any]:
    """分析 robots.txt 中公开的站点策略和路径暴露。"""
    robots_url = urljoin(start_url, "/robots.txt")
    result: Dict[str, Any] = {
        "enabled": True,
        "status": "missing",
        "robots_url": robots_url,
        "exists": False,
        "allow_paths": [],
        "disallow_paths": [],
        "sitemap_urls": [],
        "findings": [],
        "warnings": [],
    }

    check_stop(stop_event)
    try:
        response = http_request(session, "GET", robots_url, allow_redirects=True)
    except Exception as exc:
        result["status"] = "error"
        result["warnings"].append(f"robots.txt 请求失败：{exc}")
        return result

    if response.status_code >= 400:
        if response.status_code in {404, 410}:
            result["status"] = "missing"
        elif response.status_code in {401, 403}:
            result["status"] = "blocked"
            result["warnings"].append(f"robots.txt 访问被拒绝（HTTP {response.status_code}）。")
        else:
            result["status"] = "error"
            result["warnings"].append(f"robots.txt 返回异常状态码：{response.status_code}")
        return result

    text = (response.text or "").strip()
    if not text:
        result["status"] = "error"
        result["warnings"].append("robots.txt 返回内容为空。")
        return result

    result["exists"] = True
    result["status"] = "ok"
    directives = _parse_robots(text, robots_url)
    result["allow_paths"] = directives["allow_paths"]
    result["disallow_paths"] = directives["disallow_paths"]
    result["sitemap_urls"] = directives["sitemap_urls"]
    result["findings"].extend(_classify_policy_paths(directives["allow_paths"], "Allow"))
    result["findings"].extend(_classify_policy_paths(directives["disallow_paths"], "Disallow"))
    result["findings"].extend(_classify_sitemap_urls(start_url, directives["sitemap_urls"]))

    if not directives["allow_paths"] and not directives["disallow_paths"] and not directives["sitemap_urls"]:
        result["warnings"].append("robots.txt 中未发现可分析的 Allow、Disallow 或 Sitemap 规则。")

    return result


def _parse_robots(text: str, robots_url: str) -> Dict[str, List[str]]:
    """提取 robots.txt 中的常见指令。"""
    allow_paths: List[str] = []
    disallow_paths: List[str] = []
    sitemap_urls: List[str] = []
    seen_allow: set[str] = set()
    seen_disallow: set[str] = set()
    seen_sitemap: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue

        if key == "allow" and value not in seen_allow:
            seen_allow.add(value)
            allow_paths.append(value)
        elif key == "disallow" and value not in seen_disallow:
            seen_disallow.add(value)
            disallow_paths.append(value)
        elif key == "sitemap":
            sitemap_url = _normalize_robot_reference(robots_url, value)
            if sitemap_url and sitemap_url not in seen_sitemap:
                seen_sitemap.add(sitemap_url)
                sitemap_urls.append(sitemap_url)

    return {
        "allow_paths": allow_paths,
        "disallow_paths": disallow_paths,
        "sitemap_urls": sitemap_urls,
    }


def _normalize_robot_reference(robots_url: str, value: str) -> str:
    """把 robots.txt 里的相对引用规范化成绝对地址。"""
    candidate = value.strip()
    if not candidate:
        return ""
    if candidate.startswith(("http://", "https://")):
        return candidate
    return urljoin(robots_url, candidate)


def _classify_policy_paths(paths: List[str], directive: str) -> List[Dict[str, Any]]:
    """识别 robots 规则里的高信号路径。"""
    findings: List[Dict[str, Any]] = []
    for path in paths:
        normalized = path.strip()
        if not normalized:
            continue
        for pattern, risk, label, message, suggestion in _POLICY_PATTERNS:
            if pattern.search(normalized):
                findings.append(
                    {
                        "risk": risk,
                        "type": label,
                        "directive": directive,
                        "path": normalized,
                        "message": message.format(path=normalized),
                        "suggestion": suggestion,
                    }
                )
                break
    return findings


def _classify_sitemap_urls(start_url: str, sitemap_urls: List[str]) -> List[Dict[str, Any]]:
    """识别 robots.txt 中声明的 sitemap 地址是否存在异常。"""
    findings: List[Dict[str, Any]] = []
    start = urlparse(start_url)
    start_host = _normalize_host(start.hostname or "")
    for sitemap_url in sitemap_urls:
        parsed = urlparse(sitemap_url)
        if parsed.scheme not in {"http", "https"}:
            continue
        same_host = _normalize_host(parsed.hostname or "") == start_host
        if parsed.scheme == "http" and start.scheme == "https" and same_host:
            findings.append(
                {
                    "risk": "中",
                    "type": "明文 Sitemap",
                    "url": sitemap_url,
                    "message": f"robots.txt 公开了明文 sitemap 地址：{sitemap_url}",
                    "suggestion": "优先使用 HTTPS sitemap 地址，避免暴露可被降级访问的入口。",
                }
            )
        elif not same_host:
            findings.append(
                {
                    "risk": "中",
                    "type": "跨域 Sitemap",
                    "url": sitemap_url,
                    "message": f"robots.txt 指向了不同站点的 sitemap：{sitemap_url}",
                    "suggestion": "确认 sitemap 是否应由当前站点公开，避免把站点入口指向第三方域名。",
                }
            )
    return findings


def _normalize_host(host: str) -> str:
    """归一化主机名，忽略常见的 www 前缀。"""
    normalized = host.rstrip(".").lower()
    if normalized.startswith("www."):
        return normalized[4:]
    return normalized

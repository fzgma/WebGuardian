"""sitemap.xml 站点公开入口分析。"""


from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

import requests

from utils.control import check_stop
from utils.net import http_request

_MAX_SITEMAP_DEPTH = 5
_MAX_SITEMAP_DOCS = 50
_MAX_EXPORTED_URLS = 10
_MAX_EXPORTED_FINDINGS = 10


def scan_sitemap(
    session: requests.Session,
    start_url: str,
    sitemap_urls: List[str] | None = None,
    *,
    stop_event=None,
) -> Dict[str, Any]:
    """解析 sitemap.xml 并抽取可继续分析的页面入口。"""
    candidates = _unique_urls(sitemap_urls or [urljoin(start_url, "/sitemap.xml")])
    result: Dict[str, Any] = {
        "enabled": True,
        "status": "missing",
        "candidate_urls": candidates[:_MAX_EXPORTED_URLS],
        "candidate_url_count": len(candidates),
        "candidate_urls_truncated": len(candidates) > _MAX_EXPORTED_URLS,
        "documents": [],
        "discovered_urls": [],
        "discovered_url_count": 0,
        "discovered_urls_truncated": False,
        "seed_urls": [],
        "seed_url_count": 0,
        "seed_urls_truncated": False,
        "findings": [],
        "finding_count": 0,
        "findings_truncated": False,
        "highest_risk": "无",
        "warnings": [],
        "sitemap_count": 0,
        "url_count": 0,
    }

    visited: Set[str] = set()
    discovered_seen: Set[str] = set()
    seed_seen: Set[str] = set()
    lastmods: List[datetime] = []
    finding_state = {
        "count": 0,
        "highest_risk": "无",
    }

    for candidate in candidates:
        check_stop(stop_event)
        _scan_document(
            session,
            candidate,
            start_url,
            visited=visited,
            documents=result["documents"],
            findings=result["findings"],
            finding_state=finding_state,
            warnings=result["warnings"],
            discovered_urls=result["discovered_urls"],
            discovered_seen=discovered_seen,
            seed_urls=result["seed_urls"],
            seed_seen=seed_seen,
            lastmods=lastmods,
            depth=0,
            stop_event=stop_event,
        )
        if len(visited) >= _MAX_SITEMAP_DOCS:
            result["warnings"].append("sitemap 嵌套层级或文件数量过多，已提前停止继续递归。")
            break

    if lastmods and len(lastmods) >= 10:
        unique_lastmods = {item.isoformat() for item in lastmods}
        if len(unique_lastmods) == 1:
            _record_finding(
                result["findings"],
                finding_state,
                {
                    "risk": "低",
                    "type": "统一 lastmod",
                    "message": "sitemap 中大量 URL 使用了相同的 lastmod，可能缺少精细更新信息。",
                    "suggestion": "检查 sitemap 生成逻辑，确保 lastmod 反映真实的页面更新时间。",
                },
            )

    result["sitemap_count"] = len(result["documents"])
    result["seed_url_count"] = len(seed_seen)
    result["discovered_url_count"] = len(discovered_seen)
    result["seed_urls_truncated"] = result["seed_url_count"] > len(result["seed_urls"])
    result["discovered_urls_truncated"] = result["discovered_url_count"] > len(result["discovered_urls"])
    result["finding_count"] = finding_state["count"]
    result["findings_truncated"] = finding_state["count"] > len(result["findings"])
    result["highest_risk"] = finding_state["highest_risk"]
    if result["findings_truncated"]:
        result["warnings"].append(
            f"sitemap 发现项过多，已只保留前 {_MAX_EXPORTED_FINDINGS} 条样本。"
        )
    result["url_count"] = result["seed_url_count"]
    result["status"] = _summarize_status(result["documents"])
    return result


def _scan_document(
    session: requests.Session,
    sitemap_url: str,
    start_url: str,
    *,
    visited: Set[str],
    documents: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    finding_state: Dict[str, Any],
    warnings: List[str],
    discovered_urls: List[str],
    discovered_seen: Set[str],
    seed_urls: List[str],
    seed_seen: Set[str],
    lastmods: List[datetime],
    depth: int,
    stop_event=None,
) -> None:
    """递归解析单个 sitemap 文件。"""
    if len(visited) >= _MAX_SITEMAP_DOCS:
        if "sitemap 嵌套层级或文件数量过多，已提前停止继续递归。" not in warnings:
            warnings.append("sitemap 嵌套层级或文件数量过多，已提前停止继续递归。")
        return

    normalized = _normalize_url(sitemap_url)
    if not normalized or normalized in visited or depth > _MAX_SITEMAP_DEPTH:
        return

    visited.add(normalized)
    document: Dict[str, Any] = {
        "url": normalized,
        "kind": "unknown",
        "status": "ok",
        "url_count": 0,
        "sitemap_count": 0,
        "findings": [],
    }
    documents.append(document)

    check_stop(stop_event)
    try:
        response = http_request(session, "GET", normalized, allow_redirects=True)
    except Exception as exc:
        document["status"] = "error"
        document["error"] = str(exc)
        warnings.append(f"sitemap 请求失败：{normalized}，{exc}")
        return

    if response.status_code >= 400:
        if response.status_code in {404, 410}:
            document["status"] = "missing"
        elif response.status_code in {401, 403}:
            document["status"] = "blocked"
        else:
            document["status"] = "error"
        document["error"] = f"HTTP {response.status_code}"
        warnings.append(f"sitemap 返回异常状态码：{normalized}，HTTP {response.status_code}")
        return

    raw_body = response.content or b""
    if not raw_body.strip():
        document["status"] = "error"
        document["error"] = "empty body"
        warnings.append(f"sitemap 内容为空：{normalized}")
        return

    content_type = (response.headers.get("Content-Type", "") or "").lower()
    if "xml" not in content_type and not raw_body.lstrip().startswith(b"<"):
        document["status"] = "blocked" if "html" in content_type else "skipped"
        document["error"] = "non-xml body"
        warnings.append(f"sitemap 返回非 XML 内容，已跳过：{normalized}")
        return

    try:
        root = ET.fromstring(raw_body)
    except ET.ParseError as exc:
        text = (response.text or "").lstrip("\ufeff").strip()
        document["status"] = "error"
        document["error"] = str(exc)
        if text:
            try:
                root = ET.fromstring(text.encode("utf-8"))
            except ET.ParseError as retry_exc:
                document["error"] = str(retry_exc)
                warnings.append(f"sitemap XML 解析失败：{normalized}，{retry_exc}")
                return
        else:
            warnings.append(f"sitemap XML 解析失败：{normalized}，{exc}")
            return

    kind = _local_name(root.tag)
    document["kind"] = kind
    if kind == "sitemapindex":
        for sitemap_item in root:
            if _local_name(sitemap_item.tag) != "sitemap":
                continue
            sitemap_loc = _child_text(sitemap_item, "loc")
            if not sitemap_loc:
                continue
            child_url = _resolve_url(normalized, sitemap_loc)
            if not _is_http_url(child_url):
                continue
            document["sitemap_count"] += 1
            _add_entry_findings(
                start_url,
                child_url,
                findings,
                finding_state=finding_state,
                source_url=normalized,
                label="子 sitemap",
                same_site_message="sitemapindex 暴露了同站点的子 sitemap：{url}",
                cross_site_message="sitemapindex 暴露了跨站点的子 sitemap：{url}",
            )
            if _same_site(start_url, child_url):
                _scan_document(
                    session,
                    child_url,
                    start_url,
                    visited=visited,
                    documents=documents,
                    findings=findings,
                    finding_state=finding_state,
                    warnings=warnings,
                    discovered_urls=discovered_urls,
                    discovered_seen=discovered_seen,
                    seed_urls=seed_urls,
                    seed_seen=seed_seen,
                    lastmods=lastmods,
                    depth=depth + 1,
                    stop_event=stop_event,
                )
        return

    if kind != "urlset":
        document["status"] = "error"
        document["error"] = f"unexpected root: {kind or 'unknown'}"
        warnings.append(f"sitemap 根节点不是 urlset 或 sitemapindex：{normalized}")
        return

    parsed_lastmods: List[datetime] = []
    for url_item in root:
        if _local_name(url_item.tag) != "url":
            continue
        loc = _child_text(url_item, "loc")
        if not loc:
            continue

        page_url = _resolve_url(normalized, loc)
        if not _is_http_url(page_url):
            continue

        document["url_count"] += 1
        _add_entry_findings(
            start_url,
            page_url,
            findings,
            finding_state=finding_state,
            source_url=normalized,
            label="页面入口",
            same_site_message="sitemap 中公开了同站点页面入口：{url}",
            cross_site_message="sitemap 中公开了跨站点页面入口：{url}",
        )

        if _same_site(start_url, page_url):
            if page_url not in seed_seen:
                seed_seen.add(page_url)
                _append_limited(seed_urls, page_url)
            if page_url not in discovered_seen:
                discovered_seen.add(page_url)
                _append_limited(discovered_urls, page_url)

        lastmod = _child_text(url_item, "lastmod")
        if lastmod:
            parsed = _parse_lastmod(lastmod)
            if parsed is None:
                _record_finding(
                    findings,
                    finding_state,
                    {
                        "risk": "低",
                        "type": "异常 lastmod",
                        "url": page_url,
                        "message": f"sitemap 中存在无法解析的 lastmod：{lastmod}",
                        "suggestion": "检查 sitemap 生成器输出的时间格式是否符合标准 ISO 时间。",
                    },
                )
            elif _is_future_lastmod(parsed):
                parsed_lastmods.append(parsed)
                lastmods.append(parsed)
                _record_finding(
                    findings,
                    finding_state,
                    {
                        "risk": "低",
                        "type": "未来 lastmod",
                        "url": page_url,
                        "message": f"sitemap 中的 lastmod 处于未来时间：{lastmod}",
                        "suggestion": "检查服务器时钟和 sitemap 生成逻辑，避免写入未来时间。",
                    },
                )
            else:
                parsed_lastmods.append(parsed)
                lastmods.append(parsed)

    if document["url_count"] and len(parsed_lastmods) >= 10:
        unique_lastmods = {item.isoformat() for item in parsed_lastmods}
        if len(unique_lastmods) == 1:
            _record_finding(
                findings,
                finding_state,
                {
                    "risk": "低",
                    "type": "统一 lastmod",
                    "url": normalized,
                    "message": f"sitemap 文件 {normalized} 中大部分 URL 使用了相同的 lastmod。",
                    "suggestion": "检查该 sitemap 是否按页面真实更新时间输出 lastmod。",
                },
            )


def _add_entry_findings(
    start_url: str,
    target_url: str,
    findings: List[Dict[str, Any]],
    *,
    source_url: str,
    label: str,
    same_site_message: str,
    cross_site_message: str,
    finding_state: Dict[str, Any],
) -> None:
    """补充 sitemap 条目的暴露面提示。"""
    parsed = urlparse(target_url)
    if parsed.scheme == "http" and urlparse(start_url).scheme == "https" and _same_site(start_url, target_url):
        _record_finding(
            findings,
            finding_state,
            {
                "risk": "中",
                "type": f"明文 {label}",
                "url": target_url,
                "source": source_url,
                "message": f"sitemap 暴露了明文 {label}：{target_url}",
                "suggestion": "优先使用 HTTPS 页面入口，避免公开可被降级访问的地址。",
            },
        )
        return

    if _same_site(start_url, target_url):
        _record_finding(
            findings,
            finding_state,
            {
                "risk": "低",
                "type": label,
                "url": target_url,
                "source": source_url,
                "message": same_site_message.format(url=target_url),
                "suggestion": "确认这些入口是否需要被公开，避免把不必要的页面列入 sitemap。",
            },
        )
    else:
        _record_finding(
            findings,
            finding_state,
            {
                "risk": "中",
                "type": f"跨站点 {label}",
                "url": target_url,
                "source": source_url,
                "message": cross_site_message.format(url=target_url),
                "suggestion": "确认是否需要把跨站点资源写入当前站点的 sitemap。",
            },
        )


def _summarize_status(documents: List[Dict[str, Any]]) -> str:
    """汇总 sitemap 解析状态。"""
    if not documents:
        return "missing"

    statuses = {doc.get("status", "ok") for doc in documents}
    if statuses <= {"missing"}:
        return "missing"
    if "skipped" in statuses:
        return "partial"
    if "error" in statuses or "blocked" in statuses:
        return "partial" if "ok" in statuses else "error"
    if "missing" in statuses:
        return "partial"
    return "ok"


def _unique_urls(urls: List[str]) -> List[str]:
    """去重并保留原有顺序。"""
    seen: Set[str] = set()
    result: List[str] = []
    for url in urls:
        normalized = _normalize_url(url)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _append_limited(items: List[str], value: str) -> bool:
    """向列表追加条目，但只保留有限样本。"""
    if len(items) >= _MAX_EXPORTED_URLS:
        return False
    items.append(value)
    return True


def _record_finding(
    findings: List[Dict[str, Any]],
    finding_state: Dict[str, Any],
    finding: Dict[str, Any],
) -> None:
    """记录发现并控制导出样本数量。"""
    finding_state["count"] += 1
    risk = finding.get("risk", "低")
    order = {"低": 0, "中": 1, "高": 2}
    if risk in order and (
        finding_state["highest_risk"] == "无" or order[risk] > order.get(finding_state["highest_risk"], -1)
    ):
        finding_state["highest_risk"] = risk

    if len(findings) < _MAX_EXPORTED_FINDINGS:
        findings.append(finding)


def _is_future_lastmod(parsed: datetime) -> bool:
    """判断 lastmod 是否明显晚于当前日期。"""
    current = datetime.now(timezone.utc)
    if parsed.tzinfo is not None:
        current = current.astimezone(parsed.tzinfo)
    return parsed.date() > current.date()


def _normalize_url(value: str) -> str:
    """把候选地址规范化为可请求的绝对地址。"""
    candidate = (value or "").strip()
    if not candidate:
        return ""
    if candidate.startswith(("http://", "https://")):
        return candidate
    return candidate


def _resolve_url(base_url: str, value: str) -> str:
    """把 sitemap 里的引用解析成绝对地址。"""
    candidate = (value or "").strip()
    if not candidate:
        return ""
    if candidate.startswith(("http://", "https://")):
        return candidate
    return urljoin(base_url, candidate)


def _is_http_url(value: str) -> bool:
    """判断地址是否是可抓取的 HTTP(S) 地址。"""
    scheme = urlparse(value).scheme.lower()
    return scheme in {"http", "https"}


def _same_site(base_url: str, candidate_url: str) -> bool:
    """判断两个地址是否属于同一个站点。"""
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return bool(
        base.hostname
        and candidate.hostname
        and base.scheme in {"http", "https"}
        and candidate.scheme in {"http", "https"}
        and _normalize_host(base.hostname) == _normalize_host(candidate.hostname)
    )


def _normalize_host(host: str) -> str:
    """归一化主机名，忽略常见的 www 前缀。"""
    normalized = host.rstrip(".").lower()
    if normalized.startswith("www."):
        return normalized[4:]
    return normalized


def _parse_lastmod(value: str) -> datetime | None:
    """解析 sitemap lastmod。"""
    text = (value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text[:-1] + "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _local_name(tag: str) -> str:
    """移除 XML 命名空间。"""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child_text(parent: ET.Element, name: str) -> str:
    """获取子节点文本。"""
    for child in parent:
        if _local_name(child.tag) == name:
            return (child.text or "").strip()
    return ""

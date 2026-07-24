"""robots.txt / sitemap.xml 站点公开入口分析。"""

from typing import Any, Dict, List
from urllib.parse import urljoin

import requests

from utils.control import check_stop
from .crawl_policy import scan_crawl_policy
from .sitemap import scan_sitemap


def scan_sitecheck(
    session: requests.Session,
    start_url: str,
    *,
    stop_event=None,
) -> Dict[str, Any]:
    """统一分析 robots.txt 和 sitemap.xml。"""
    check_stop(stop_event)
    crawl_policy = scan_crawl_policy(session, start_url, stop_event=stop_event)
    sitemap_candidates = _candidate_sitemaps(start_url, crawl_policy.get("sitemap_urls", []))

    check_stop(stop_event)
    sitemap = scan_sitemap(session, start_url, sitemap_candidates, stop_event=stop_event)

    findings = _merge_findings(crawl_policy.get("findings", []), sitemap.get("findings", []))
    warnings = _merge_texts(crawl_policy.get("warnings", []), sitemap.get("warnings", []))
    risk_counts = _merge_risk_counts(crawl_policy.get("findings", []), sitemap.get("findings", []))
    crawl_finding_count = len(crawl_policy.get("findings", []))
    sitemap_finding_count = sitemap.get("finding_count", len(sitemap.get("findings", [])))
    highest_risk = _combine_highest_risk(
        _highest_risk(crawl_policy.get("findings", [])),
        sitemap.get("highest_risk", "无"),
    )
    result: Dict[str, Any] = {
        "enabled": True,
        "status": _combine_status(crawl_policy.get("status", "missing"), sitemap.get("status", "missing")),
        "robots_url": crawl_policy.get("robots_url", urljoin(start_url, "/robots.txt")),
        "crawl_policy": crawl_policy,
        "sitemap": sitemap,
        "seed_urls": sitemap.get("seed_urls", []),
        "discovered_urls": sitemap.get("discovered_urls", []),
        "findings": findings,
        "warnings": warnings,
        "finding_count": crawl_finding_count + sitemap_finding_count,
        "risk_counts": risk_counts,
        "seed_url_count": sitemap.get("seed_url_count", len(sitemap.get("seed_urls", []))),
        "discovered_url_count": sitemap.get("discovered_url_count", len(sitemap.get("discovered_urls", []))),
        "sitemap_url_count": len(crawl_policy.get("sitemap_urls", [])),
        "highest_risk": highest_risk,
    }
    return result


def _candidate_sitemaps(start_url: str, sitemap_urls: List[str]) -> List[str]:
    """整理 sitemap 候选地址。"""
    candidates: List[str] = []
    seen: set[str] = set()
    for url in list(sitemap_urls) + [urljoin(start_url, "/sitemap.xml")]:
        candidate = (url or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)
    return candidates


def _merge_findings(*groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """合并暴露面发现并保持顺序。"""
    merged: List[Dict[str, Any]] = []
    for group in groups:
        merged.extend(group or [])
    return merged


def _merge_texts(*groups: List[str]) -> List[str]:
    """合并提示文本并去重。"""
    merged: List[str] = []
    seen: set[str] = set()
    for group in groups:
        for text in group or []:
            candidate = (text or "").strip()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            merged.append(candidate)
    return merged


def _combine_status(crawl_status: str, sitemap_status: str) -> str:
    """汇总站点公开入口分析状态。"""
    statuses = {crawl_status, sitemap_status}
    if statuses <= {"missing"}:
        return "missing"
    if "error" in statuses and "ok" in statuses:
        return "partial"
    if "error" in statuses or "blocked" in statuses:
        return "partial" if "ok" in statuses or "missing" in statuses else "error"
    if "partial" in statuses:
        return "partial"
    if "missing" in statuses:
        return "partial"
    return "ok"


def _highest_risk(findings: List[Dict[str, Any]]) -> str:
    """计算最高风险等级。"""
    order = {"低": 0, "中": 1, "高": 2}
    highest = "无"
    for finding in findings:
        risk = finding.get("risk")
        if risk in order and (highest == "无" or order[risk] > order[highest]):
            highest = risk
    return highest


def _merge_risk_counts(*groups: List[Dict[str, Any]]) -> Dict[str, int]:
    """汇总风险等级计数。"""
    counts = {"低": 0, "中": 0, "高": 0}
    for group in groups:
        for finding in group or []:
            risk = finding.get("risk")
            if risk in counts:
                counts[risk] += 1
    return counts


def _combine_highest_risk(*risks: str) -> str:
    """合并多个最高风险等级。"""
    order = {"无": -1, "低": 0, "中": 1, "高": 2}
    highest = "无"
    for risk in risks:
        if risk in order and order[risk] > order[highest]:
            highest = risk
    return highest

"""页面级安全扫描编排。"""

from collections import deque
from threading import Event
from typing import Callable, Deque, Dict, List, Set, Tuple, cast
from urllib.parse import urljoin

import requests

from scanner.basescan.header_rules import assess_security_headers
from scanner.options import ScanOptions
from utils.control import check_stop
from utils.net import http_request
from .page_checks import (
    PageParser,
    cookie_security_findings,
    detect_exposed_info,
    extract_redirect_chain,
    is_html,
    is_same_host,
    is_same_origin,
    resolve_links,
)
from .page_results import PageScanResults
from .sitecheck import scan_sitecheck


def scan_pages(
    session: requests.Session,
    start_url: str,
    options: ScanOptions,
    *,
    max_pages: int = 10,
    max_depth: int = 2,
    progress_callback: Callable[[int, str], None] | None = None,
    stop_event: Event | None = None,
) -> Dict[str, object]:
    """执行同源页面级安全检查。"""
    results = PageScanResults()
    visited: Set[str] = set()
    queue: Deque[Tuple[str, int]] = deque([(start_url, 0)])
    scanned_urls: List[str] = []
    pages_scanned = 0
    pages_attempted = 0
    pages_failed = 0
    pages_skipped = 0
    last_progress = (-1, "")

    enabled_checks = _enabled_checks(options)
    if not enabled_checks:
        message = "页面级扫描已启用，但未选择具体检查项。"
        results.warnings.append(message)
        return results.to_dict(0, max_pages, max_depth, [], message, assessment="not_applicable")

    page_checks = [name for name in enabled_checks if name != "check_page_sitecheck"]
    page_work_units = 1 + len(page_checks)
    total_work = max(
        1, (max_pages * page_work_units if page_checks else 0) + int(options.check_page_sitecheck)
    )
    completed_work = 0

    def update_progress(percent: int, text: str) -> None:
        """向外汇报页面扫描进度。"""
        nonlocal last_progress
        percent = min(100, max(0, percent))
        if progress_callback and (percent, text) != last_progress:
            last_progress = (percent, text)
            progress_callback(percent, text)

    def complete_work(text: str) -> None:
        """完成当前页面的一项检查工作。"""
        nonlocal completed_work
        check_stop(stop_event)
        completed_work += 1
        # 页面级进度按整体工作量折算。
        update_progress(round(completed_work / total_work * 100), text)

    def skip_remaining_checks(page_start_work: int, text: str) -> None:
        """跳过当前页面未执行的检查项。"""
        # 跳过的检查也要补足工作量，避免进度卡住。
        page_progress = completed_work - page_start_work
        for _ in range(max(0, page_work_units - page_progress)):
            complete_work(text)

    if options.check_page_sitecheck:
        check_stop(stop_event)
        update_progress(0, "正在分析 robots.txt 和 sitemap.xml")
        results.sitecheck = scan_sitecheck(session, start_url, stop_event=stop_event)
        raw_seed_urls: object = (
            results.sitecheck.get("seed_urls", []) if results.sitecheck else []
        )
        seed_items = cast(list[object], raw_seed_urls) if isinstance(raw_seed_urls, list) else []
        seed_urls = [
            url for url in seed_items
            if isinstance(url, str) and is_same_origin(start_url, url)
        ]
        queue.extend((url, 0) for url in seed_urls)
        results.warnings.extend(results.sitecheck.get("warnings", []))
        complete_work("站点公开入口分析")

    if not page_checks:
        queue.clear()
    update_progress(round(completed_work / total_work * 100), "正在准备页面级安全检查")
    while queue and pages_attempted < max_pages:
        check_stop(stop_event)
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth or not is_same_origin(start_url, current_url):
            continue

        page_start_work = completed_work
        visited.add(current_url)
        scanned_urls.append(current_url)
        pages_attempted += 1
        page_label = f"页面 {pages_attempted}/{max_pages}"

        try:
            response = http_request(session, "GET", current_url, allow_redirects=True)
            response.raise_for_status()
        except Exception as exc:
            pages_failed += 1
            message = f"页面请求失败 {current_url}：{exc}"
            results.warnings.append(message)
            results.diagnostics.append({"url": current_url, "status": "failed", "reason": "request_error", "message": message})
            complete_work(f"{page_label}：请求页面")
            skip_remaining_checks(page_start_work, f"{page_label}：页面不可访问，跳过检查")
            continue

        complete_work(f"{page_label}：请求页面")
        final_url = response.url
        _check_redirects(response, current_url, start_url, options, results)
        if options.check_page_redirects:
            complete_work(f"{page_label}：重定向链")
        if not is_same_origin(start_url, final_url):
            # 跨源后不再继续解析当前页。
            pages_skipped += 1
            results.diagnostics.append({"url": current_url, "final_url": final_url, "status": "skipped", "reason": "cross_origin_redirect"})
            skip_remaining_checks(page_start_work, f"{page_label}：跨源跳转，跳过检查")
            continue
        if not is_html(response.headers.get("Content-Type", "")):
            # 只检查 HTML 页面。
            pages_skipped += 1
            results.diagnostics.append({"url": current_url, "status": "skipped", "reason": "non_html"})
            skip_remaining_checks(page_start_work, f"{page_label}：非 HTML 页面，跳过检查")
            continue

        check_stop(stop_event)
        parser = PageParser()
        body = response.text or ""
        parser.feed(body)
        base_url = response.url
        _run_page_checks(response, base_url, body, parser, options, results, complete_work, page_label)
        pages_scanned += 1
        results.diagnostics.append({"url": current_url, "final_url": base_url, "status": "complete"})
        queue.extend((link, depth + 1) for link in resolve_links(base_url, parser.links))

    update_progress(100, "页面级安全检查完成")
    assessment = _assessment(results, bool(page_checks), pages_scanned, pages_failed, pages_skipped)
    return results.to_dict(
        pages_scanned, max_pages, max_depth, scanned_urls,
        pages_attempted=pages_attempted, pages_failed=pages_failed,
        pages_skipped=pages_skipped, assessment=assessment,
    )


def _assessment(
    results: PageScanResults,
    page_checks_enabled: bool,
    pages_scanned: int,
    pages_failed: int,
    pages_skipped: int,
) -> str:
    """根据实际完成范围评价证据完整性，不把执行失败视为安全风险。"""
    states: list[str] = []
    if page_checks_enabled:
        cross_origin_skips = any(item.get("reason") == "cross_origin_redirect" for item in results.diagnostics)
        if pages_scanned:
            states.append("partial" if pages_failed or cross_origin_skips else "complete")
        elif pages_failed or cross_origin_skips:
            states.append("unknown")
        else:
            states.append("not_applicable")
    if results.sitecheck is not None:
        status = results.sitecheck.get("status")
        child_statuses = [
            cast(Dict[str, object], child).get("status")
            for child in (results.sitecheck.get("crawl_policy"), results.sitecheck.get("sitemap"))
            if isinstance(child, dict)
        ]
        # 聚合状态的 partial 也可能仅表示一个文件存在、另一个明确不存在。
        if len(child_statuses) == 2 and all(child in ("ok", "missing") for child in child_statuses):
            status = "ok"
        states.append(
            "complete" if status in {"ok", "missing"}
            else "partial" if status == "partial" else "unknown"
        )
    applicable = [state for state in states if state != "not_applicable"]
    if not applicable:
        return "not_applicable"
    if all(state == "complete" for state in applicable):
        return "complete"
    if all(state == "unknown" for state in applicable):
        return "unknown"
    return "partial"


def _enabled_checks(options: ScanOptions) -> List[str]:
    """返回启用的页面检查项。"""
    return [
        name for name in (
            "check_page_redirects", "check_page_headers", "check_page_cookie_flags",
            "check_page_mixed_content", "check_page_forms", "check_page_exposed_info",
            "check_page_sitecheck",
        ) if getattr(options, name)
    ]


def _check_redirects(response: requests.Response, current_url: str, start_url: str, options: ScanOptions, results: PageScanResults) -> None:
    """检查页面重定向风险。"""
    chain = extract_redirect_chain(response, current_url)
    if len(chain) > 1:
        results.redirect_chains.append({"url": current_url, "chain": chain})
    if not options.check_page_redirects:
        return

    for hop in response.history:
        previous = getattr(getattr(hop, "request", None), "url", "") or current_url
        current = hop.url
        results.redirect_issues.append({"from": previous, "to": current, "status_code": hop.status_code})
        if previous.startswith("https://") and current.startswith("http://"):
            results.add_finding("高", "downgrade_redirect", previous, "页面重定向链中出现从 HTTPS 到 HTTP 的降级跳转。", "移除会降级协议的跳转，确保 HTTPS 请求不会被导向 HTTP 页面。")
        if not is_same_host(start_url, current):
            results.add_finding("高", "cross_origin_redirect", previous, "页面发生了跨源跳转。", "检查跳转目标是否为可信域名，避免将用户导向第三方站点。")

    if not is_same_host(start_url, response.url):
        results.add_finding("高", "cross_origin_redirect", current_url, "页面发生了跨源跳转。", "检查跳转目标是否为可信域名，避免将用户导向第三方站点。")


def _run_page_checks(response: requests.Response, base_url: str, body: str, parser: PageParser, options: ScanOptions, results: PageScanResults, complete_work: Callable[[str], None], page_label: str) -> None:
    """执行单页安全检查。"""
    if options.check_page_cookie_flags:
        cookie_findings = cookie_security_findings(response)
        cookie_count = len(response.cookies)
        results.cookie_checks.append({
            "url": base_url,
            "status": "complete" if cookie_count else "not_applicable",
            "cookies_checked": cookie_count,
            "findings": cookie_findings,
        })
        for finding in cookie_findings:
            results.add_finding(
                "中", "cookie_flags", base_url,
                f"Cookie {finding['name']}（域：{finding['domain'] or '当前主机'}，路径：{finding['path']}）缺少或使用无效的安全属性：{', '.join(finding['missing_flags'])}",
                "为敏感 Cookie 启用 Secure、HttpOnly，并设置有效的 SameSite 属性。",
                evidence=dict(finding),
            )
        complete_work(f"{page_label}：Cookie 安全属性")

    if options.check_page_headers:
        header_result = assess_security_headers(response.headers, ("Content-Security-Policy", "Strict-Transport-Security"))
        missing = header_result["missing"]
        if missing:
            results.add_finding("中", "missing_headers", base_url, f"页面缺少安全响应头：{', '.join(missing)}", "为重点页面补充 CSP 和 HSTS 等安全头。")
        for invalid in header_result["invalid"]:
            results.add_finding(
                "中", "invalid_header", base_url,
                f"页面安全响应头 {invalid['header']} 无效或策略不足：{invalid['reason']}",
                "为重点页面配置有效的 CSP 和 HSTS 策略。", evidence=invalid,
            )
        complete_work(f"{page_label}：页面安全头")

    if options.check_page_mixed_content:
        if base_url.startswith("https://"):
            for resource in parser.resources:
                resource_url = urljoin(base_url, resource)
                if resource_url.startswith("http://"):
                    results.add_finding("高", "mixed_content", base_url, f"发现不安全资源：{resource_url}", "将页面资源统一切换为 HTTPS，避免混合内容。")
        complete_work(f"{page_label}：混合内容")

    if options.check_page_forms:
        if base_url.startswith("https://"):
            for form in parser.forms:
                action = form.get("action", "").strip()
                action_url = urljoin(base_url, action)
                if action and action_url.startswith("http://"):
                    results.add_finding("高", "insecure_form", base_url, f"表单提交地址使用了不安全协议：{action_url}", "将表单 action 修改为 HTTPS 地址。")
        complete_work(f"{page_label}：不安全表单")

    if options.check_page_exposed_info:
        matched, risk = detect_exposed_info(body)
        if matched:
            results.add_finding("中" if risk == "中" else "低", "exposed_info", base_url, "页面源码中发现可疑暴露信息：" + "；".join(matched), "检查页面源码、前端配置与构建产物，移除测试地址、调试标记和内网引用。")
        complete_work(f"{page_label}：暴露信息")

"""页面级安全扫描编排。"""

from collections import deque
from typing import Callable, Deque, Dict, List, Set, Tuple
from urllib.parse import urljoin

import requests

from .net import http_request
from .options import ScanOptions
from .page_checks import (
    PageParser,
    cookie_flag_state,
    detect_exposed_info,
    extract_redirect_chain,
    is_html,
    is_same_origin,
    resolve_links,
)
from .page_results import PageScanResults


def scan_pages(
    session: requests.Session,
    start_url: str,
    options: ScanOptions,
    *,
    max_pages: int = 10,
    max_depth: int = 2,
    progress_callback: Callable[[int, str], None] | None = None,
) -> Dict[str, object]:
    """执行同源页面级安全检查。"""
    results = PageScanResults()
    visited: Set[str] = set()
    queue: Deque[Tuple[str, int]] = deque([(start_url, 0)])
    scanned_urls: List[str] = []
    pages_scanned = 0
    last_progress = (-1, "")

    enabled_checks = _enabled_checks(options)
    if not enabled_checks:
        message = "页面级扫描已启用，但未选择具体检查项。"
        results.warnings.append(message)
        return results.to_dict(0, max_pages, max_depth, [], message)

    page_work_units = 1 + len(enabled_checks)
    completed_work = 0

    def update_progress(percent: int, text: str) -> None:
        """向外汇报页面扫描进度。"""
        nonlocal last_progress
        if progress_callback and (percent, text) != last_progress:
            last_progress = (percent, text)
            progress_callback(percent, text)

    def complete_work(text: str) -> None:
        """完成当前页面的一项检查工作。"""
        nonlocal completed_work
        completed_work += 1
        update_progress(round(completed_work / (max_pages * page_work_units) * 100), text)

    def skip_remaining_checks(text: str) -> None:
        """跳过当前页面未执行的检查项。"""
        for _ in range(page_work_units - completed_work % page_work_units):
            complete_work(text)

    update_progress(0, "正在准备页面级安全检查")
    while queue and pages_scanned < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue

        visited.add(current_url)
        scanned_urls.append(current_url)
        pages_scanned += 1
        page_label = f"页面 {pages_scanned}/{max_pages}"

        try:
            response = http_request(session, "GET", current_url, allow_redirects=True)
        except Exception as exc:
            results.add_finding("中", "request_error", current_url, f"页面请求失败：{exc}", "确认页面是否可访问，或降低扫描深度后重试。")
            complete_work(f"{page_label}：请求页面")
            skip_remaining_checks(f"{page_label}：页面不可访问，跳过检查")
            continue

        complete_work(f"{page_label}：请求页面")
        final_url = response.url
        _check_redirects(response, current_url, start_url, options, results)
        if options.check_page_redirects:
            complete_work(f"{page_label}：重定向链")
        if options.check_page_redirects and not is_same_origin(start_url, final_url):
            skip_remaining_checks(f"{page_label}：跨源跳转，跳过检查")
            continue
        if not is_html(response.headers.get("Content-Type", "")):
            skip_remaining_checks(f"{page_label}：非 HTML 页面，跳过检查")
            continue

        parser = PageParser()
        body = response.text or ""
        parser.feed(body)
        base_url = response.url
        _run_page_checks(response, base_url, body, parser, options, results, complete_work, page_label)
        queue.extend((link, depth + 1) for link in resolve_links(base_url, parser.links))

    update_progress(100, "页面级安全检查完成")
    return results.to_dict(pages_scanned, max_pages, max_depth, scanned_urls)


def _enabled_checks(options: ScanOptions) -> List[str]:
    """返回启用的页面检查项。"""
    return [
        name for name in (
            "check_page_redirects", "check_page_headers", "check_page_cookie_flags",
            "check_page_mixed_content", "check_page_forms", "check_page_exposed_info",
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
        if not is_same_origin(start_url, current):
            results.add_finding("高", "cross_origin_redirect", previous, "页面发生了跨源跳转。", "检查跳转目标是否为可信域名，避免将用户导向第三方站点。")

    if not is_same_origin(start_url, response.url):
        results.add_finding("高", "cross_origin_redirect", current_url, "页面发生了跨源跳转。", "检查跳转目标是否为可信域名，避免将用户导向第三方站点。")


def _run_page_checks(response: requests.Response, base_url: str, body: str, parser: PageParser, options: ScanOptions, results: PageScanResults, complete_work: Callable[[str], None], page_label: str) -> None:
    """执行单页安全检查。"""
    if options.check_page_cookie_flags:
        flags = cookie_flag_state(response)
        if not all(flags.values()):
            results.add_finding("中", "cookie_flags", base_url, f"Cookie 安全属性不完整：Secure={flags['secure']}, HttpOnly={flags['httponly']}, SameSite={flags['samesite']}", "为敏感 Cookie 启用 Secure、HttpOnly 和 SameSite。")
        complete_work(f"{page_label}：Cookie 安全属性")

    if options.check_page_headers:
        names = {name.lower() for name in response.headers}
        missing = [name.upper() for name in ("content-security-policy", "strict-transport-security") if name not in names]
        if missing:
            results.add_finding("中", "missing_headers", base_url, f"页面缺少安全响应头：{', '.join(missing)}", "为重点页面补充 CSP 和 HSTS 等安全头。")
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

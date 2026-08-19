import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests

from scanner.basescan import (
    SENSITIVE_PATHS,
    run_base_checks,
    run_dns_check,
    run_tls_check,
)
from utils.control import check_stop
from utils.availability import build_availability_result
from utils.net import (
    http_request,
    make_availability_session,
    make_session,
    normalize_url,
    validate_input_url,
)
from utils.result_composer import (
    build_target_result,
    compose_scan_error,
    compose_scan_result,
    wrap_section_result,
)
from utils.timer import Timer
from .options import ScanOptions
from .pagecheck.page_scan import scan_pages
from utils.scan_progress import ScanProgress
from utils.security_score import calculate_score


@dataclass
class ScanContext:
    """保存一次扫描所需的目标和运行态信息。"""

    input_url: str
    normalized_url: str
    parsed: Any
    host: str
    resolved_ips: List[str]
    scan_options: ScanOptions
    session: requests.Session
    progress: ScanProgress
    stop_event: Any = None
    errors: list[str] = field(default_factory=list)


def resolve_host_ips(host: str) -> List[str]:
    """解析主机名对应的 IP 地址。"""
    if not host:
        return []

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []

    ips: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in ips:
            ips.append(address) # type: ignore
    return ips


def _create_scan_context(
    url: str,
    progress_callback=None,
    options: Dict[str, Any] | ScanOptions | None = None,
    stop_event=None,
) -> ScanContext | str:
    """初始化扫描上下文。"""
    scan_options = (
        options if isinstance(options, ScanOptions) else ScanOptions.from_dict(options)
    )
    if scan_options.enabled_items() == 0:
        return "请至少启用一项检测后再开始扫描。"

    ok, msg = validate_input_url(url)
    if not ok:
        return msg

    progress = ScanProgress(
        scan_options,
        len(SENSITIVE_PATHS),
        progress_callback,
        stop_event=stop_event,
    )
    session = make_session()

    check_stop(stop_event)
    normalized_url = normalize_url(url, session)
    parsed = urlparse(normalized_url)
    host = parsed.hostname or ""

    return ScanContext(
        input_url=url,
        normalized_url=normalized_url,
        parsed=parsed,
        host=host,
        resolved_ips=resolve_host_ips(host),
        scan_options=scan_options,
        session=session,
        progress=progress,
        stop_event=stop_event,
    )


def _request_target(
    normalized_url: str,
    progress: ScanProgress,
) -> Tuple[requests.Response | None, Dict[str, Any] | None, Dict[str, Any] | None]:
    """请求目标站点并统一处理错误。"""
    progress.update("正在请求目标站点")
    request_timer = Timer()
    session = make_availability_session()
    try:
        try:
            response = http_request(
                session,
                "GET",
                normalized_url,
                stream=True,
                raise_for_status=True,
            )
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "未知"
            return None, {"ok": False, "error": f"目标站点返回异常状态码：{code}"}, None
        except Exception as exc:
            return None, {"ok": False, "error": f"无法访问站点：{exc}"}, None

        availability_timings: dict[str, float] = {}
        raw = getattr(response, "raw", None)
        connection = getattr(raw, "_connection", None)
        if connection is not None:
            timings = getattr(connection, "_availability_timings", None)
            if isinstance(timings, dict):
                availability_timings = dict(timings)

        # 读取响应体，确保总耗时和响应大小是本次正式请求的真实结果。
        _ = response.content
        availability = build_availability_result(
            response,
            total_seconds=round(request_timer.elapsed_seconds(), 6),
            timings=availability_timings,
        )

        progress.update("目标站点请求完成", 1)
        return response, None, availability
    finally:
        session.close()


def _empty_page_scan_result() -> Dict[str, Any]:
    """返回未启用页面扫描时的 section 数据。"""
    return {
        "enabled": False,
        "status": "disabled",
        "pages_scanned": 0,
        "max_pages": 0,
        "max_depth": 0,
        "finding_count": 0,
        "page_findings": 0,
        "highest_risk": "无",
        "findings": [],
        "risk_counts": {"低": 0, "中": 0, "高": 0},
        "sitecheck": None,
        "visited_urls": [],
        "redirect_issues": [],
        "redirect_chains": [],
        "warnings": [],
        "message": "",
    }


def _run_page_scan(
    context: ScanContext,
) -> Dict[str, Any] | None:
    """调用页面级扫描模块。"""
    check_stop(context.stop_event)
    page_scan = scan_pages(
        context.session,
        context.normalized_url,
        context.scan_options,
        max_pages=context.scan_options.page_scan_max_pages,
        max_depth=context.scan_options.page_scan_max_depth,
        progress_callback=context.progress.page_callback(context.scan_options),
        stop_event=context.stop_event,
    )
    context.progress.complete_page_scan(context.scan_options)
    return page_scan


def scan(
    url: str,
    progress_callback=None,
    options: Dict[str, Any] | ScanOptions | None = None,
    stop_event=None,
) -> Dict[str, Any]:
    """按固定顺序编排一次站点安全扫描。"""
    timer = Timer()
    context = _create_scan_context(url, progress_callback, options, stop_event)
    if isinstance(context, str):
        return compose_scan_error(context, round(timer.elapsed_seconds(), 2))

    target = build_target_result(
        context.input_url,
        context.normalized_url,
        context.host,
        context.resolved_ips,
    )
    response, error, availability = _request_target(
        context.normalized_url,
        context.progress,
    )
    if error is not None:
        return compose_scan_error(
            error.get("error", "目标站点请求失败。"),
            round(timer.elapsed_seconds(), 2),
        )
    if response is None:
        return compose_scan_error(
            "目标站点请求失败。",
            round(timer.elapsed_seconds(), 2),
        )

    check_stop(context.stop_event)
    checks = run_base_checks(context, response)
    checks = {
        "availability": wrap_section_result(
            "availability",
            availability or {},
            enabled=True,
            status="ok",
            summary="网站可用性观测完成。",
        ),
        **checks,
    }
    checks["tls"] = run_tls_check(context, response)
    checks["dns_security"] = run_dns_check(context)

    if context.scan_options.check_page_scan:
        page_scan = _run_page_scan(context)
        checks["page_scan"] = wrap_section_result(
            "page_scan",
            page_scan,
            enabled=True,
            status=page_scan.get("status", "ok")
            if isinstance(page_scan, Mapping)
            else "ok",
            summary="页面级安全检查完成。",
            warnings=page_scan.get("warnings", [])
            if isinstance(page_scan, Mapping)
            else None,
            findings=page_scan.get("findings", [])
            if isinstance(page_scan, Mapping)
            else None,
        )
    else:
        checks["page_scan"] = wrap_section_result(
            "page_scan",
            _empty_page_scan_result(),
            enabled=False,
            status="disabled",
            summary="页面级安全检查未启用。",
        )

    score, level = calculate_score({"checks": checks}, context.scan_options)
    final_result = compose_scan_result(
        target=target,
        checks=checks,
        score=score,
        level=level,
        elapsed_seconds=round(timer.elapsed_seconds(), 2),
        page_scan=checks.get("page_scan"),
        errors=context.errors,
        warnings=[],
    )

    check_stop(context.stop_event)
    context.progress.update("检测完成", 1)
    return final_result

"""扫描后端编排测试。"""

from typing import cast
from unittest.mock import patch
from urllib.parse import urlparse

import requests

from result_model.composer import wrap_section_result
from result_model.models import JsonObject, ScanContext, ScanResult, ScoreReport, SectionStatus
from runtime.scan_progress import ScanProgress
from scanner import scanner as scanner_module
from scanner.basescan import dns as dns_module
from scanner.options import ScanOptions


def test_scan_assembles_successful_backend_result() -> None:
    """扫描入口应汇总各检测 section、评分和完成进度。"""
    options = ScanOptions(check_page_scan=False, check_sensitive_paths=False)
    progress_events: list[tuple[int, str]] = []

    def record_progress(percent: int, text: str) -> None:
        progress_events.append((percent, text))

    progress = ScanProgress(options, 0, record_progress)
    context = ScanContext(
        input_url="example.com",
        normalized_url="https://example.com",
        parsed=urlparse("https://example.com"),
        host="example.com",
        resolved_ips=["93.184.216.34"],
        scan_options=options,
        session=requests.Session(),
        progress=progress,
    )
    response = cast(requests.Response, object())
    availability: JsonObject = {"dns_seconds": 0.01, "total_bytes": 512}
    base_checks = {
        "https": wrap_section_result(
            "https", {"value": True}, enabled=True, status=SectionStatus.OK
        )
    }
    tls = wrap_section_result("tls", {"ssl_valid": True}, enabled=True, status=SectionStatus.OK)
    dns = wrap_section_result(
        "dns_security", {"domain": "example.com"}, enabled=True, status=SectionStatus.OK
    )

    with (
        patch.object(scanner_module, "_create_scan_context", return_value=context),
        patch.object(scanner_module, "_request_target", return_value=(response, None, availability)),
        patch.object(scanner_module, "run_base_checks", return_value=base_checks),
        patch.object(scanner_module, "run_tls_check", return_value=tls),
        patch.object(scanner_module, "run_dns_check", return_value=dns),
        patch.object(scanner_module, "calculate_score_report", return_value=ScoreReport(score=88, level="A级", status="complete")),
    ):
        result = scanner_module.scan("example.com", progress_callback=record_progress)

    assert isinstance(result, ScanResult)
    assert result.ok is True
    assert result.target.normalized_url == "https://example.com"
    assert result.target.host == "example.com"
    assert set(result.checks) == {"availability", "https", "tls", "dns_security", "page_scan"}
    assert result.checks["availability"].value("total_bytes") == 512
    assert result.summary.score == 88
    assert result.summary.level == "A级"
    assert result.summary.scoring.score == 88
    assert set(result.summary.module_durations) == {
        "目标站点请求",
        "基础检测",
        "TLS/SSL 检测",
        "DNS 安全检测",
    }
    assert all(duration >= 0 for duration in result.summary.module_durations.values())
    assert result.summary.page_scan_summary["enabled"] is False
    assert progress_events[-1][1] == "检测完成"


def test_dns_progress_advances_for_each_record_type() -> None:
    """DNS 检测应在 SPF、DMARC 和 CAA 查询完成后分别推进进度。"""
    options = ScanOptions(
        check_https=False,
        check_ssl=False,
        check_dns_security=True,
        check_security_headers=False,
        check_trace=False,
        check_sensitive_paths=False,
        check_info_leak=False,
    )
    progress_events: list[tuple[int, str]] = []

    def record_progress(percent: int, text: str) -> None:
        progress_events.append((percent, text))

    progress = ScanProgress(options, 0, record_progress)
    with (
        patch.object(dns_module, "_lookup_txt_records", return_value=([], [])),
        patch.object(dns_module, "_lookup_caa_records", return_value=({"records": [], "issuers": []}, [])),
    ):
        result = dns_module._detect_dns_security("example.com", progress=progress)

    completed_texts = [text for _percent, text in progress_events]
    assert result["status"] == "ok"
    assert "SPF 查询完成：example.com" in completed_texts
    assert "DMARC 查询完成：example.com" in completed_texts
    assert "CAA 查询完成：example.com" in completed_texts
    assert progress.completed_work == 3


def test_request_duration_does_not_include_later_check_durations() -> None:
    """目标请求耗时应在请求返回时冻结，不能与后续检测阶段重叠。"""
    options = ScanOptions(check_page_scan=False, check_sensitive_paths=False)
    context = ScanContext(
        input_url="example.com",
        normalized_url="https://example.com",
        parsed=urlparse("https://example.com"),
        host="example.com",
        resolved_ips=[],
        scan_options=options,
        session=requests.Session(),
        progress=ScanProgress(options, 0, None),
    )
    clock = {"seconds": 0.0}

    class FakeTimer:
        """用可控时间验证各阶段边界。"""

        def __init__(self) -> None:
            self.started_at = clock["seconds"]

        def elapsed_seconds(self) -> float:
            return clock["seconds"] - self.started_at

    def request_target(_url: str, _progress: ScanProgress) -> tuple[requests.Response, None, JsonObject]:
        clock["seconds"] += 1.0
        return cast(requests.Response, object()), None, {}

    def base_checks(_context: ScanContext, _response: requests.Response) -> dict[str, object]:
        clock["seconds"] += 2.0
        return {"https": wrap_section_result("https", {"value": True}, enabled=True)}

    def tls_check(_context: ScanContext, _response: requests.Response) -> object:
        clock["seconds"] += 3.0
        return wrap_section_result("tls", {"ssl_valid": True}, enabled=True)

    def dns_check(_context: ScanContext) -> object:
        clock["seconds"] += 4.0
        return wrap_section_result("dns_security", {}, enabled=True)

    with (
        patch.object(scanner_module, "Timer", FakeTimer),
        patch.object(scanner_module, "_create_scan_context", return_value=context),
        patch.object(scanner_module, "_request_target", side_effect=request_target),
        patch.object(scanner_module, "run_base_checks", side_effect=base_checks),
        patch.object(scanner_module, "run_tls_check", side_effect=tls_check),
        patch.object(scanner_module, "run_dns_check", side_effect=dns_check),
        patch.object(scanner_module, "calculate_score_report", return_value=ScoreReport(score=100, level="A级", status="complete")),
    ):
        result = scanner_module.scan("example.com", options=options)

    assert result.summary.elapsed_seconds == 10.0
    assert result.summary.module_durations == {
        "目标站点请求": 1.0,
        "基础检测": 2.0,
        "TLS/SSL 检测": 3.0,
        "DNS 安全检测": 4.0,
    }

"""安全评分加分规则测试。"""

from result_model.composer import wrap_section_result
from dataclasses import fields

import pytest

from result_model.models import SectionStatus
from result_model.security_score import calculate_score, calculate_score_report
from scanner.options import ScanOptions


def test_all_secure_enabled_checks_receive_full_score() -> None:
    """所有已启用检查满足加分条件时应得到 A 级满分。"""
    options = ScanOptions()
    checks = {
        "https": wrap_section_result("https", {"value": True}, enabled=True),
        "tls": wrap_section_result(
            "tls",
            {
                "ssl_valid": True,
                "ssl_days_left": 30,
                "supported_protocols": ["TLS 1.2", "TLS 1.3"],
                "weak_protocols": [],
                "cipher_weak": False,
                "chain_complete": True,
            },
            enabled=True,
        ),
        "dns_security": wrap_section_result(
            "dns_security",
            {
                "spf": {"policy": "strict"},
                "dmarc": {"policy": "reject"},
                "caa": {"present": True, "issuers": ["letsencrypt.org"]},
            },
            enabled=True,
        ),
        "security_headers": wrap_section_result("security_headers", {"score": 30}, enabled=True),
        "info_leak": wrap_section_result(
            "info_leak",
            {"version_exposed": False, "framework_exposed": False, "meta_exposed": False},
            enabled=True,
        ),
        "http_methods": wrap_section_result(
            "http_methods", {"trace_enabled": False, "exposed_methods": []}, enabled=True
        ),
        "sensitive_paths": wrap_section_result("sensitive_paths", {"paths": []}, enabled=True),
    }

    score, level = calculate_score(checks, options)

    assert (score, level) == (100, "A级")


def test_disabled_checks_do_not_reduce_https_only_score() -> None:
    """关闭的检查不应进入分母，HTTPS 单项也应正确归一化。"""
    options = ScanOptions(
        check_ssl=False,
        check_dns_security=False,
        check_security_headers=False,
        check_trace=False,
        check_sensitive_paths=False,
        check_info_leak=False,
    )
    checks = {"https": wrap_section_result("https", {"value": True}, enabled=True)}

    assert calculate_score(checks, options) == (100, "A级")


def _only(*enabled: str) -> ScanOptions:
    return ScanOptions(**{
        item.name: item.name in enabled
        for item in fields(ScanOptions) if item.name.startswith("check_")
    })


def test_page_only_has_no_baseline_score_or_grade() -> None:
    report = calculate_score_report({}, _only("check_page_scan", "check_page_headers"))
    assert report.score is None
    assert report.level == "不适用"
    assert report.status == "not_applicable"
    assert report.enabled_count == 0


def test_https_only_reports_limited_scope() -> None:
    report = calculate_score_report(
        {"https": wrap_section_result("https", {"value": True}, enabled=True)},
        _only("check_https"),
    )
    assert (report.score, report.level) == (100, "A级")
    assert (report.enabled_count, report.total_count, report.evaluated_count) == (1, 7, 1)
    assert report.items[0].earned == 10
    assert sum(item.status == "disabled" for item in report.items) == 6


@pytest.mark.parametrize("assessment", ["partial", "unknown"])
def test_failed_paths_never_receive_full_score_or_grade(assessment: str) -> None:
    paths = wrap_section_result(
        "sensitive_paths", {"paths": [], "meta": {"assessment": assessment}},
        enabled=True, warnings=["请求超时"],
    )
    report = calculate_score_report({"sensitive_paths": paths}, _only("check_sensitive_paths"))
    assert report.score is None
    assert report.level == "待完成"
    assert report.unknown_count == 1
    assert report.items[-1].earned is None
    assert "超时" in report.items[-1].reason


def test_legacy_paths_warning_cannot_be_treated_as_success() -> None:
    paths = wrap_section_result("sensitive_paths", {"paths": []}, enabled=True, warnings=["timeout"])
    assert calculate_score({"sensitive_paths": paths}, _only("check_sensitive_paths"))[0] is None


def test_partial_report_keeps_known_points_without_overall_grade() -> None:
    checks = {
        "https": wrap_section_result("https", {"value": True}, enabled=True),
        "sensitive_paths": wrap_section_result("sensitive_paths", {}, enabled=True, status=SectionStatus.ERROR),
    }
    report = calculate_score_report(checks, _only("check_https", "check_sensitive_paths"))
    assert (report.score, report.level, report.status) == (None, "待完成", "partial")
    assert (report.earned_points, report.possible_points) == (10, 20)
    assert (report.evaluated_count, report.unknown_count) == (1, 1)


def test_enabled_missing_section_is_unknown_instead_of_omitted() -> None:
    report = calculate_score_report({}, _only("check_https"))
    assert report.status == "unknown"
    assert report.enabled_count == report.unknown_count == 1


def test_ip_dns_is_not_applicable_and_does_not_reduce_https_score() -> None:
    checks = {
        "https": wrap_section_result("https", {"value": True}, enabled=True),
        "dns_security": wrap_section_result("dns_security", {}, enabled=True, status=SectionStatus.SKIPPED),
    }
    report = calculate_score_report(checks, _only("check_https", "check_dns_security"))
    assert report.score == 100
    assert report.not_applicable_count == 1
    assert report.possible_points == 10


def test_confirmed_risk_is_scored_instead_of_unknown() -> None:
    checks = {"https": wrap_section_result("https", {"value": False}, enabled=True)}
    report = calculate_score_report(checks, _only("check_https"))
    assert (report.score, report.level, report.status) == (0, "C级", "complete")
    assert report.items[0].status == "risk"


def test_malformed_enabled_payload_is_unknown() -> None:
    report = calculate_score_report(
        {"tls": wrap_section_result("tls", {"ssl_valid": True}, enabled=True)}, _only("check_ssl")
    )
    assert report.score is None
    assert report.unknown_count == 1

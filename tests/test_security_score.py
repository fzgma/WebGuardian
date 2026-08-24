"""安全评分加分规则测试。"""

from result_model.composer import wrap_section_result
from result_model.security_score import calculate_score
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

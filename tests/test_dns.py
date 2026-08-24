"""DNS 检测结果包装测试。"""

from unittest.mock import patch
from urllib.parse import urlparse

import requests

from result_model.models import ScanContext, SectionStatus
from runtime.scan_progress import ScanProgress
from scanner.basescan import dns
from scanner.options import ScanOptions


def _context(options: ScanOptions) -> ScanContext:
    """创建 DNS 检测所需的最小扫描上下文。"""
    return ScanContext(
        input_url="example.com",
        normalized_url="https://example.com",
        parsed=urlparse("https://example.com"),
        host="example.com",
        resolved_ips=[],
        scan_options=options,
        session=requests.Session(),
        progress=ScanProgress(options, 0, None),
    )


def test_dns_check_wraps_fake_dns_data_and_findings() -> None:
    """DNS 探测返回的记录、warning 和 finding 应完整传入 section。"""
    options = ScanOptions(check_sensitive_paths=False)
    detected: dict[str, object] = {
        "status": "warn",
        "domain": "example.com",
        "lookup_domain": "example.com",
        "spf": {"present": True, "records": ["v=spf1 -all"], "policy": "strict"},
        "dmarc": {"present": True, "records": ["v=DMARC1; p=reject"], "policy": "reject"},
        "caa": {"present": True, "records": ['0 issue "letsencrypt.org"'], "issuers": ["letsencrypt.org"]},
        "warnings": ["DNS 查询使用了备用解析器。"],
        "findings": [
            {
                "risk": "低",
                "type": "DNS 安全配置",
                "message": "配置完整。",
                "suggestion": "定期复核。",
            }
        ],
    }
    context = _context(options)

    with patch.object(dns, "_detect_dns_security", return_value=detected):
        result = dns.run_dns_check(context)

    assert result.enabled is True
    assert result.status is SectionStatus.WARN
    assert result.value("spf") == detected["spf"]
    assert result.value("dmarc") == detected["dmarc"]
    assert result.value("caa") == detected["caa"]
    assert result.warnings == ["DNS 查询使用了备用解析器。"]
    assert result.findings[0].get("type") == "DNS 安全配置"


def test_dns_check_returns_disabled_section_without_lookup() -> None:
    """关闭 DNS 时不应执行 DNS 查询。"""
    options = ScanOptions(check_dns_security=False, check_sensitive_paths=False)

    with patch.object(dns, "_detect_dns_security") as detect:
        result = dns.run_dns_check(_context(options))

    detect.assert_not_called()
    assert result.enabled is False
    assert result.status is SectionStatus.DISABLED
    assert result.value("domain") == "example.com"

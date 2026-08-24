"""TLS 检测结果包装测试。"""

from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

import requests

from runtime.scan_progress import ScanProgress
from scanner.basescan import tls
from scanner.options import ScanOptions
from result_model.models import ScanContext, SectionStatus


def _context(options: ScanOptions) -> ScanContext:
    """创建 TLS 检测所需的最小扫描上下文。"""
    return ScanContext(
        input_url="https://example.com",
        normalized_url="https://example.com",
        parsed=urlparse("https://example.com"),
        host="example.com",
        resolved_ips=[],
        scan_options=options,
        session=requests.Session(),
        progress=ScanProgress(options, 0, None),
    )


def test_tls_check_wraps_successful_inspection_result() -> None:
    """TLS 成功结果应保留证书和协议数据，并推进进度。"""
    options = ScanOptions(check_sensitive_paths=False)
    inspected: dict[str, object] = {
        "ok": True,
        "ssl_valid": True,
        "ssl_days_left": 45,
        "protocol": "TLSv1.3",
        "cipher": {"cipher_name": "TLS_AES_128_GCM_SHA256", "cipher_bits": 128},
        "chain_complete": True,
        "certificate": {"subject": "CN=example.com", "issuer": "CN=Test CA"},
        "warnings": ["证书链信息不完整或仅返回了单张证书。"],
    }
    context = _context(options)

    with patch.object(tls, "inspect_tls_configuration", return_value=inspected):
        result = tls.run_tls_check(context, SimpleNamespace(url="https://example.com"))

    assert result.enabled is True
    assert result.status is SectionStatus.OK
    assert result.value("ssl_valid") is True
    assert result.value("protocol") == "TLSv1.3"
    assert result.value("chain_complete") is True
    assert result.value("certificate") == {"subject": "CN=example.com", "issuer": "CN=Test CA"}
    assert result.warnings == ["证书链信息不完整或仅返回了单张证书。"]
    assert context.progress.completed_work == 1


def test_tls_check_returns_disabled_section_without_network_inspection() -> None:
    """关闭 TLS 时不应触发 TLS 探测。"""
    options = ScanOptions(check_ssl=False, check_sensitive_paths=False)

    with patch.object(tls, "inspect_tls_configuration") as inspect:
        result = tls.run_tls_check(_context(options), SimpleNamespace(url="https://example.com"))

    inspect.assert_not_called()
    assert result.enabled is False
    assert result.status is SectionStatus.DISABLED
    assert result.value("ssl_valid") is None

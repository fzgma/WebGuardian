"""核心扫描结果模型和展示转换测试。"""

import unittest

from ui.result.composer import build_result_view_model, wrap_section_result
from ui.result.models import (
    AvailabilityViewData,
    DnsViewData,
    FindingView,
    PageScanViewData,
    ScanResult,
    SectionStatus,
    TargetResult,
    TlsViewData,
)


class ResultModelTests(unittest.TestCase):
    """验证核心结果模型的构造和序列化边界。"""

    def test_scan_result_serializes_flat_section_payload(self) -> None:
        """结果模型应保留既有扁平 section JSON 语义。"""
        section = wrap_section_result(
            "https",
            {"value": True, "warnings": ["提示"]},
            enabled=True,
            status=SectionStatus.OK,
            summary="HTTPS 检测完成。",
        )
        result = ScanResult(
            ok=True,
            target=TargetResult(url="https://example.com"),
            checks={"https": section},
        )

        serialized = result.to_dict()
        self.assertTrue(serialized["ok"])
        checks = serialized["checks"]
        self.assertIsInstance(checks, dict)
        https = checks["https"]
        self.assertIsInstance(https, dict)
        self.assertTrue(https["value"])
        self.assertEqual(https["status"], "ok")
        self.assertEqual(https["warnings"], ["提示"])

    def test_view_model_converts_dynamic_payload_once(self) -> None:
        """展示模型应集中转换 TLS、DNS、可用性和页面扫描数据。"""
        sections = {
            "availability": wrap_section_result(
                "availability",
                {"dns_seconds": 0.01, "total_bytes": 2048},
                enabled=True,
            ),
            "https": wrap_section_result("https", {"value": True}, enabled=True),
            "tls": wrap_section_result(
                "tls",
                {
                    "ssl_valid": True,
                    "cipher": {
                        "cipher_name": "TLS_AES_128_GCM_SHA256",
                        "cipher_bits": 128,
                    },
                    "certificate": {"subject": "CN=example.com"},
                },
                enabled=True,
            ),
            "dns_security": wrap_section_result(
                "dns_security",
                {
                    "domain": "example.com",
                    "spf": {"present": True, "records": ["v=spf1"]},
                },
                enabled=True,
            ),
            "page_scan": wrap_section_result(
                "page_scan",
                {
                    "enabled": True,
                    "pages_scanned": 2,
                    "finding_count": 1,
                    "findings": [
                        {"risk": "中", "type": "页面问题", "url": "https://example.com"}
                    ],
                    "risk_counts": {"中": 1},
                    "sitecheck": {
                        "enabled": True,
                        "status": "ok",
                        "seed_url_count": 1,
                    },
                },
                enabled=True,
            ),
        }
        result = ScanResult(ok=True, checks=sections)

        view_model = build_result_view_model(result)

        self.assertIsInstance(view_model.sections.availability.data, AvailabilityViewData)
        self.assertEqual(view_model.sections.availability.data.total_bytes, 2048)
        self.assertIsInstance(view_model.sections.tls.data, TlsViewData)
        self.assertEqual(view_model.sections.tls.data.cipher.cipher_bits, 128)
        self.assertIsInstance(view_model.sections.dns_security.data, DnsViewData)
        self.assertTrue(view_model.sections.dns_security.data.spf.present)
        self.assertIsInstance(view_model.sections.page_scan.data, PageScanViewData)
        self.assertEqual(view_model.sections.page_scan.data.pages_scanned, 2)
        self.assertEqual(view_model.sections.page_scan.data.sitecheck.seed_url_count, 1)
        self.assertIsInstance(view_model.sections.page_scan.findings[0], FindingView)


if __name__ == "__main__":
    unittest.main()

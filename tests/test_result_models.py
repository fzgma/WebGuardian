"""核心扫描结果模型和展示转换测试。"""

import unittest
from typing import cast

from result_model.composer import build_result_view_model, wrap_section_result
from result_model.models import (
    AvailabilityViewData,
    DnsViewData,
    FindingView,
    JsonValue,
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
        checks = _json_object(serialized["checks"])
        https = _json_object(checks["https"])
        self.assertTrue(https["value"])
        self.assertEqual(https["status"], "ok")
        self.assertEqual(https["warnings"], ["提示"])

    def test_view_model_converts_dynamic_payload_once(self) -> None:
        """展示模型应集中转换 TLS、DNS、可用性和页面扫描数据。"""
        page_scan_payload: dict[str, object] = {
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
            "redirect_issues": [
                {
                    "status_code": 301,
                    "from": "https://example.com",
                    "to": "https://www.example.com",
                }
            ],
        }
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
                page_scan_payload,
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
        self.assertTrue(view_model.overview.page_scan.enabled)
        self.assertIs(view_model.overview.https, view_model.sections.https)
        self.assertEqual(view_model.sections.page_scan.data.pages_scanned, 2)
        sitecheck = view_model.sections.page_scan.data.sitecheck
        if sitecheck is None:
            self.fail("页面扫描应包含 sitecheck 展示数据")
        self.assertEqual(sitecheck.seed_url_count, 1)
        self.assertIsInstance(view_model.sections.page_scan.findings[0], FindingView)

        serialized = view_model.to_dict()
        overview = _json_object(serialized["overview"])
        page_scan = _json_object(overview["page_scan"])
        serialized_sitecheck = _json_object(page_scan["sitecheck"])
        self.assertTrue(serialized_sitecheck["enabled"])
        self.assertEqual(serialized_sitecheck["status"], "ok")
        self.assertEqual(serialized_sitecheck["seed_url_count"], 1)
        self.assertEqual(
            page_scan["redirect_issues"],
            [{"status_code": 301, "from": "https://example.com", "to": "https://www.example.com"}],
        )


def _json_object(value: JsonValue) -> dict[str, JsonValue]:
    """把测试中的递归 JSON 值收窄为对象。"""
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object, got {type(value).__name__}")
    return cast(dict[str, JsonValue], value)


if __name__ == "__main__":
    unittest.main()

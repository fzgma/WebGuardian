"""扫描后端编排测试。"""

import unittest
from typing import cast
from unittest.mock import patch
from urllib.parse import urlparse

import requests

from scanner import scanner as scanner_module
from scanner.basescan import dns as dns_module
from scanner.options import ScanOptions
from result_model.composer import wrap_section_result
from result_model.models import JsonObject, ScanContext, ScanResult, SectionStatus
from runtime.scan_progress import ScanProgress


class ScannerTests(unittest.TestCase):
    """验证后端扫描入口的编排结果。"""

    def test_scan_assembles_successful_backend_result(self) -> None:
        """扫描入口应汇总各检测 section、评分和完成进度。"""
        options = ScanOptions(
            check_page_scan=False,
            check_sensitive_paths=False,
        )
        progress_events: list[tuple[int, str]] = []

        def record_progress(percent: int, text: str) -> None:
            """记录测试中的进度通知。"""
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
                "https",
                {"value": True},
                enabled=True,
                status=SectionStatus.OK,
            )
        }
        tls = wrap_section_result(
            "tls",
            {"ssl_valid": True},
            enabled=True,
            status=SectionStatus.OK,
        )
        dns = wrap_section_result(
            "dns_security",
            {"domain": "example.com"},
            enabled=True,
            status=SectionStatus.OK,
        )

        with (
            patch.object(scanner_module, "_create_scan_context", return_value=context),
            patch.object(
                scanner_module,
                "_request_target",
                return_value=(response, None, availability),
            ),
            patch.object(scanner_module, "run_base_checks", return_value=base_checks),
            patch.object(scanner_module, "run_tls_check", return_value=tls),
            patch.object(scanner_module, "run_dns_check", return_value=dns),
            patch.object(
                scanner_module,
                "calculate_score",
                return_value=(88, "A级"),
            ),
        ):
            result = scanner_module.scan("example.com", progress_callback=record_progress)

        self.assertIsInstance(result, ScanResult)
        self.assertTrue(result.ok)
        self.assertEqual(result.target.normalized_url, "https://example.com")
        self.assertEqual(result.target.host, "example.com")
        self.assertEqual(
            set(result.checks),
            {"availability", "https", "tls", "dns_security", "page_scan"},
        )
        self.assertEqual(result.checks["availability"].value("total_bytes"), 512)
        self.assertEqual(result.summary.score, 88)
        self.assertEqual(result.summary.level, "A级")
        self.assertFalse(result.summary.page_scan_summary["enabled"])
        self.assertEqual(progress_events[-1][1], "检测完成")

    def test_dns_progress_advances_for_each_record_type(self) -> None:
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
            """记录 DNS 查询进度。"""
            progress_events.append((percent, text))

        progress = ScanProgress(options, 0, record_progress)

        with (
            patch.object(dns_module, "_lookup_txt_records", return_value=([], [])),
            patch.object(
                dns_module,
                "_lookup_caa_records",
                return_value=({"records": [], "issuers": []}, []),
            ),
        ):
            result = dns_module._detect_dns_security("example.com", progress=progress)

        self.assertEqual(result["status"], "ok")
        completed_texts = [text for _percent, text in progress_events]
        self.assertIn("SPF 查询完成：example.com", completed_texts)
        self.assertIn("DMARC 查询完成：example.com", completed_texts)
        self.assertIn("CAA 查询完成：example.com", completed_texts)
        self.assertEqual(progress.completed_work, 3)


if __name__ == "__main__":
    unittest.main()

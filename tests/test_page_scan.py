"""页面扫描的证据完整性、计数和范围回归测试。"""

import json
from typing import Any, cast
from unittest.mock import patch

import pytest
import requests
from requests.cookies import create_cookie

from scanner.options import ScanOptions
from scanner.pagecheck import page_scan


def _response(url: str = "https://example.com", *, body: str = "", content_type: str = "text/html", status: int = 200) -> requests.Response:
    response = requests.Response()
    response.url = url
    response.status_code = status
    response.headers["Content-Type"] = content_type
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    return response


def _items(result: dict[str, object], field: str) -> list[dict[str, Any]]:
    value = result[field]
    assert isinstance(value, list)
    return cast(list[dict[str, Any]], value)


def test_cookie_scan_records_each_cookie_without_values() -> None:
    response = _response()
    response.cookies.set_cookie(create_cookie(
        "safe", "private-safe-value", secure=True, rest={"HttpOnly": None, "SameSite": "Lax"},
    ))
    response.cookies.set_cookie(create_cookie("unsafe", "private-unsafe-value", rest={}))
    with patch.object(page_scan, "http_request", return_value=response):
        result = page_scan.scan_pages(requests.Session(), response.url, ScanOptions(check_page_cookie_flags=True))

    assert result["finding_count"] == 1
    assert _items(result, "findings")[0]["evidence"]["name"] == "unsafe"
    assert _items(result, "cookie_checks")[0]["cookies_checked"] == 2
    assert result["pages_scanned"] == result["pages_attempted"] == 1
    assert result["assessment"] == "complete"
    assert "private-" not in json.dumps(result)


def test_page_without_cookies_records_not_applicable_cookie_evidence() -> None:
    with patch.object(page_scan, "http_request", return_value=_response()):
        result = page_scan.scan_pages(requests.Session(), "https://example.com", ScanOptions(check_page_cookie_flags=True))

    assert result["findings"] == []
    assert result["cookie_checks"] == [{
        "url": "https://example.com", "status": "not_applicable", "cookies_checked": 0, "findings": [],
    }]


@pytest.mark.parametrize("failure", [requests.Timeout("timed out"), _response(status=503)])
def test_request_failure_is_unknown_evidence_not_a_security_finding(failure: object) -> None:
    with patch.object(page_scan, "http_request", side_effect=[failure]):
        result = page_scan.scan_pages(requests.Session(), "https://example.com", ScanOptions(check_page_cookie_flags=True))

    assert result["pages_attempted"] == result["pages_failed"] == 1
    assert result["pages_scanned"] == result["pages_skipped"] == 0
    assert result["assessment"] == "unknown"
    assert result["findings"] == []
    assert result["risk_counts"] == {"低": 0, "中": 0, "高": 0}
    assert len(cast(list[str], result["warnings"])) == 1
    assert _items(result, "diagnostics")[0]["reason"] == "request_error"


def test_attempt_budget_counts_failed_and_skipped_pages_separately() -> None:
    responses: list[object] = [
        _response(body='<a href="/failure">F</a><a href="/file">File</a><a href="/later">Later</a>'),
        requests.Timeout("timed out"),
        _response("https://example.com/file", content_type="application/pdf"),
    ]
    with patch.object(page_scan, "http_request", side_effect=responses) as request:
        result = page_scan.scan_pages(
            requests.Session(), "https://example.com", ScanOptions(check_page_cookie_flags=True), max_pages=3,
        )

    assert request.call_count == 3
    assert result["pages_attempted"] == 3
    assert result["pages_scanned"] == result["pages_failed"] == result["pages_skipped"] == 1
    assert result["assessment"] == "partial"
    assert result["finding_count"] == 0


def test_non_html_page_is_not_reported_as_scanned_html() -> None:
    with patch.object(page_scan, "http_request", return_value=_response(content_type="application/json")):
        result = page_scan.scan_pages(requests.Session(), "https://example.com", ScanOptions(check_page_headers=True))

    assert result["pages_attempted"] == result["pages_skipped"] == 1
    assert result["pages_scanned"] == result["pages_failed"] == 0
    assert result["assessment"] == "not_applicable"
    assert result["findings"] == []


@pytest.mark.parametrize("check_redirects", [False, True])
def test_cross_origin_response_is_never_parsed_or_followed(check_redirects: bool) -> None:
    response = _response("https://other.example", body='<a href="/next">Next</a><script src="http://unsafe.example/app.js"></script>')
    options = ScanOptions(check_page_mixed_content=True, check_page_redirects=check_redirects)
    with patch.object(page_scan, "http_request", return_value=response) as request:
        result = page_scan.scan_pages(requests.Session(), "https://example.com", options)

    assert request.call_count == 1
    assert result["pages_scanned"] == 0
    assert result["pages_skipped"] == 1
    assert result["assessment"] == "unknown"
    assert all(item["type"] != "mixed_content" for item in _items(result, "findings"))
    assert _items(result, "diagnostics")[0]["reason"] == "cross_origin_redirect"


def test_sitecheck_progress_is_bounded_and_foreign_seeds_are_ignored() -> None:
    events: list[int] = []
    sitecheck: dict[str, object] = {"status": "ok", "seed_urls": ["https://foreign.example"], "warnings": []}
    with (
        patch.object(page_scan, "scan_sitecheck", return_value=sitecheck),
        patch.object(page_scan, "http_request", return_value=_response()) as request,
    ):
        result = page_scan.scan_pages(
            requests.Session(), "https://example.com",
            ScanOptions(check_page_cookie_flags=True, check_page_sitecheck=True),
            max_pages=1, progress_callback=lambda percent, _text: events.append(percent),
        )

    assert request.call_count == 1
    assert result["assessment"] == "complete"
    assert events == sorted(events)
    assert max(events) == events[-1] == 100


def test_sitecheck_only_does_not_claim_html_checks_or_request_pages() -> None:
    with (
        patch.object(page_scan, "scan_sitecheck", return_value={"status": "partial", "warnings": ["sitemap unavailable"]}),
        patch.object(page_scan, "http_request") as request,
    ):
        result = page_scan.scan_pages(requests.Session(), "https://example.com", ScanOptions(check_page_sitecheck=True))

    request.assert_not_called()
    assert result["pages_attempted"] == result["pages_scanned"] == 0
    assert result["assessment"] == "partial"
    assert result["warnings"] == ["sitemap unavailable"]


def test_page_header_checks_reject_present_but_empty_policies() -> None:
    response = _response()
    response.headers.update({"Content-Security-Policy": "", "Strict-Transport-Security": ""})
    with patch.object(page_scan, "http_request", return_value=response):
        result = page_scan.scan_pages(requests.Session(), "https://example.com", ScanOptions(check_page_headers=True))

    assert cast(int, result["finding_count"]) > 0
    assert result["assessment"] == "complete"


@pytest.mark.parametrize(("crawl_status", "sitemap_status"), [("ok", "missing"), ("missing", "ok")])
def test_sitecheck_known_absence_does_not_make_evidence_partial(crawl_status: str, sitemap_status: str) -> None:
    sitecheck: dict[str, object] = {
        "status": "partial",
        "crawl_policy": {"status": crawl_status},
        "sitemap": {"status": sitemap_status},
        "warnings": [],
    }
    with patch.object(page_scan, "scan_sitecheck", return_value=sitecheck):
        result = page_scan.scan_pages(requests.Session(), "https://example.com", ScanOptions(check_page_sitecheck=True))

    assert result["assessment"] == "complete"
    assert result["pages_attempted"] == 0


def test_non_html_link_does_not_reduce_completed_html_evidence() -> None:
    with patch.object(page_scan, "http_request", side_effect=[
        _response(body='<a href="/guide.pdf">Guide</a>'),
        _response("https://example.com/guide.pdf", content_type="application/pdf"),
    ]):
        result = page_scan.scan_pages(
            requests.Session(), "https://example.com", ScanOptions(check_page_cookie_flags=True), max_pages=2,
        )

    assert result["pages_attempted"] == 2
    assert result["pages_scanned"] == result["pages_skipped"] == 1
    assert result["pages_failed"] == 0
    assert result["assessment"] == "complete"


def test_normalized_response_origin_is_still_scanned() -> None:
    with patch.object(page_scan, "http_request", return_value=_response("https://example.com/")):
        result = page_scan.scan_pages(
            requests.Session(), "https://EXAMPLE.com:443", ScanOptions(check_page_cookie_flags=True),
        )

    assert result["pages_scanned"] == 1
    assert result["pages_skipped"] == 0
    assert result["assessment"] == "complete"

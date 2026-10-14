"""基础站点检查的离线行为测试。"""

from types import SimpleNamespace
from typing import cast
from unittest.mock import patch
from urllib.parse import urlparse

import requests
import pytest

from runtime.scan_progress import ScanProgress
from scanner.basescan import base_checks
from scanner.basescan.header_rules import assess_security_headers
from scanner.options import ScanOptions
from result_model.models import ScanContext, SectionStatus


def _context(options: ScanOptions) -> ScanContext:
    """创建不发起网络请求的基础检测上下文。"""
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


def test_run_base_checks_reports_missing_headers_and_exposure() -> None:
    """基础检查应计算安全头覆盖率并记录响应和 meta 指纹。"""
    options = ScanOptions(
        check_ssl=False,
        check_dns_security=False,
        check_trace=False,
        check_sensitive_paths=False,
    )
    response = cast(
        requests.Response,
        SimpleNamespace(
            url="https://example.com",
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "Server": "nginx/1.25.3",
                "X-Powered-By": "Express 4.18.2",
            },
            text='<meta name="generator" content="WebGuardian CMS">',
        ),
    )

    checks = base_checks.run_base_checks(_context(options), response)

    headers = checks["security_headers"]
    exposure = checks["info_leak"]
    assert headers.value("score") == 4
    missing = headers.value("missing")
    assert isinstance(missing, list)
    assert "Strict-Transport-Security" in missing
    assert exposure.value("version_exposed") is True
    assert exposure.value("framework_exposed") is True
    assert exposure.value("meta_exposed") is True
    assert {item.get("field") for item in exposure.findings} == {"Server", "X-Powered-By", "generator"}


def test_http_method_detection_separates_risky_methods_and_trace() -> None:
    """OPTIONS/CORS 声明中的副作用方法应合并，TRACE 单独判断。"""
    options_response = SimpleNamespace(
        status_code=204,
        headers={"Allow": "GET, POST, PUT", "Access-Control-Allow-Methods": "PATCH, PUT"},
    )
    trace_response = SimpleNamespace(status_code=200, headers={}, text="TRACE / HTTP/1.1\r\nHost: example.com\r\n")

    def request(_session: requests.Session, method: str, _url: str, **_kwargs: object) -> object:
        return options_response if method == "OPTIONS" else trace_response

    with patch.object(base_checks, "http_request", side_effect=request):
        result = base_checks._detect_http_methods(requests.Session(), "https://example.com")

    assert result["options_status"] == 204
    assert result["allow_methods"] == ["GET", "POST", "PUT"]
    assert result["cors_methods"] == ["PATCH", "PUT"]
    assert result["exposed_methods"] == ["PUT", "PATCH"]
    assert result["trace_enabled"] is True
    assert result["meta"]["assessment"] == "complete"


@pytest.mark.parametrize(
    ("header", "value", "expected_reason"),
    [
        ("Permissions-Policy", "  ", "为空"),
        ("Strict-Transport-Security", "max-age=0; includeSubDomains", "撤销"),
        ("Strict-Transport-Security", "max-age=-1", "非负整数"),
        ("Strict-Transport-Security", "max-age=oops", "非负整数"),
        ("Strict-Transport-Security", "max-age=123; max-age=456", "只能包含一个"),
        ("Strict-Transport-Security", "includeSubDomains", "必须包含"),
        ("X-Frame-Options", "ALLOW-FROM https://example.com", "DENY"),
        ("X-Content-Type-Options", "off", "nosniff"),
        ("Content-Security-Policy", "default-src *", "通配符"),
        ("Content-Security-Policy", "script-src data:", "data:"),
        ("Content-Security-Policy", "script-src 'unsafe-inline'", "内联"),
        ("Content-Security-Policy", "script-src 'self' 'unsafe-eval'", "unsafe-eval"),
        ("Content-Security-Policy", "frame-ancestors 'none'", "未约束脚本"),
    ],
)
def test_header_present_but_invalid_does_not_earn_credit(header: str, value: str, expected_reason: str) -> None:
    result = assess_security_headers({header.lower(): value}, (header,))
    assert result["score"] == 0
    assert result["missing"] == []
    assert result["invalid"][0]["header"] == header
    assert expected_reason in result["invalid"][0]["reason"]
    assert result["meta"]["assessment"] == "complete"


@pytest.mark.parametrize(
    "policy",
    [
        "default-src 'self'; style-src 'unsafe-inline'",
        "default-src *; script-src 'self'",
        "script-src 'unsafe-inline' 'nonce-YWJjZA=='",
        "script-src 'unsafe-inline' 'sha256-YWJjZA=='",
        "script-src * 'unsafe-inline' 'nonce-YWJjZA==' 'strict-dynamic'",
        "default-src * 'unsafe-inline' 'unsafe-eval', script-src 'none'",
        "script-src 'none'; script-src 'unsafe-inline'",
        "script-src 'unsafe-inline'; script-src-elem 'none'; script-src-attr 'none'",
        "sandbox; default-src * 'unsafe-inline' 'unsafe-eval'",
        "script-src",
    ],
)
def test_csp_effective_restrictions_avoid_false_positive(policy: str) -> None:
    result = assess_security_headers({"Content-Security-Policy": policy}, ("Content-Security-Policy",))
    assert result["invalid"] == []
    assert result["score"] == 30


def test_valid_header_values_are_case_insensitive_and_hsts_allows_quotes() -> None:
    result = assess_security_headers(
        {"strict-transport-security": 'max-age="31536000"', "x-frame-options": "sameorigin", "x-content-type-options": "NoSniff"},
        ("Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"),
    )
    assert result["score"] == 30
    assert result["invalid"] == []


def _only_path_options() -> ScanOptions:
    return ScanOptions(
        check_https=False, check_ssl=False, check_dns_security=False,
        check_security_headers=False, check_trace=False,
        check_info_leak=False, check_sensitive_paths=True,
    )


def _response(status_code: int = 200, *, headers: dict[str, str] | None = None, text: str = "") -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response.headers.update(headers or {})
    response.url = "https://example.com/"
    response._content = text.encode()
    return response


def test_sensitive_paths_keep_protected_redirect_and_failure_separate() -> None:
    paths = ["/docs", "/admin", "/console", "/backup", "/missing", "/error", "/timeout"]
    responses: list[object] = [
        _response(200), _response(401), _response(403),
        _response(302, headers={"Location": "/login"}), _response(404),
        _response(503), requests.Timeout("offline test"),
    ]
    with (
        patch.object(base_checks, "SENSITIVE_PATHS", paths),
        patch.object(base_checks, "http_request", side_effect=responses) as request,
    ):
        section = base_checks.run_base_checks(_context(_only_path_options()), _response())["sensitive_paths"]

    assert section.value("paths") == ["/docs"]
    assert section.value("checked_count") == 5
    assert section.value("failed_count") == 2
    assert section.meta["assessment"] == "partial"
    observations = section.value("observations")
    assert isinstance(observations, list)
    assert all(isinstance(item, dict) for item in observations)
    records = cast(list[dict[str, object]], observations)
    assert [item["status"] for item in records] == [
        "suspected_exposure", "protected", "protected", "redirect", "not_found", "error", "error",
    ]
    reason = records[0]["reason"]
    assert isinstance(reason, str)
    assert "soft-404" in reason
    assert all(call.kwargs["allow_redirects"] is False for call in request.call_args_list)
    assert request.call_count == len(paths)


def test_all_sensitive_path_timeouts_are_unknown_not_success() -> None:
    with (
        patch.object(base_checks, "SENSITIVE_PATHS", ["/docs", "/admin"]),
        patch.object(base_checks, "http_request", side_effect=requests.Timeout("offline test")),
    ):
        section = base_checks.run_base_checks(_context(_only_path_options()), _response())["sensitive_paths"]
    assert section.value("paths") == []
    assert section.value("checked_count") == 0
    assert section.value("failed_count") == 2
    assert section.meta["assessment"] == "unknown"
    assert section.status is SectionStatus.ERROR


@pytest.mark.parametrize("code", [401, 403, 404, 410])
def test_protected_or_absent_sensitive_paths_are_not_reported_as_exposed(code: int) -> None:
    with (
        patch.object(base_checks, "SENSITIVE_PATHS", ["/admin"]),
        patch.object(base_checks, "http_request", return_value=_response(code)),
    ):
        result = base_checks._detect_sensitive_paths(_context(_only_path_options()))
    assert result["paths"] == []
    assert result["meta"]["assessment"] == "complete"


@pytest.mark.parametrize("code", [200, 302, 401, 403, 404, 500])
def test_trace_status_alone_cannot_confirm_enablement(code: int) -> None:
    with patch.object(base_checks, "http_request", side_effect=[
        _response(204, headers={"Allow": "GET, OPTIONS"}),
        _response(code, text="<html>A generic page</html>"),
    ]):
        result = base_checks._detect_http_methods(requests.Session(), "https://example.com")
    assert result["trace_enabled"] is None
    assert result["meta"]["assessment"] == "partial"


def test_failed_options_does_not_make_other_methods_look_disabled() -> None:
    with patch.object(base_checks, "http_request", side_effect=[requests.Timeout("offline"), _response(405)]):
        result = base_checks._detect_http_methods(requests.Session(), "https://example.com")
    assert result["trace_enabled"] is False
    assert result["options_assessment"] == "unknown"
    assert result["meta"]["assessment"] == "partial"


def test_options_without_method_declaration_and_failed_trace_are_unknown() -> None:
    with patch.object(base_checks, "http_request", side_effect=[_response(204), requests.Timeout("offline")]):
        result = base_checks._detect_http_methods(requests.Session(), "https://example.com")
    assert result["exposed_methods"] == []
    assert result["meta"]["assessment"] == "unknown"

"""基础站点检查的离线行为测试。"""

from types import SimpleNamespace
from typing import cast
from unittest.mock import patch
from urllib.parse import urlparse

import requests

from runtime.scan_progress import ScanProgress
from scanner.basescan import base_checks
from scanner.options import ScanOptions
from result_model.models import ScanContext


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
    trace_response = SimpleNamespace(status_code=200, headers={})

    def request(_session: requests.Session, method: str, _url: str, **_kwargs: object) -> object:
        return options_response if method == "OPTIONS" else trace_response

    with patch.object(base_checks, "http_request", side_effect=request):
        result = base_checks._detect_http_methods(requests.Session(), "https://example.com")

    assert result["options_status"] == 204
    assert result["allow_methods"] == ["GET", "POST", "PUT"]
    assert result["cors_methods"] == ["PATCH", "PUT"]
    assert result["exposed_methods"] == ["PUT", "PATCH"]
    assert result["trace_enabled"] is True

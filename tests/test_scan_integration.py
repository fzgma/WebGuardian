"""用本地 HTTP 服务验证采集、判定、评分和结果展示边界的完整链路。"""

from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from result_model.composer import build_result_view_model
from scanner.options import ScanOptions
from scanner.scanner import scan


@pytest.fixture
def target_server() -> Iterator[tuple[str, dict[str, str]]]:
    state = {"mode": "normal"}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/":
                status = 200
            elif self.path == "/admin":
                status = 401
            elif self.path == "/backup" and state["mode"] == "failed_path":
                status = 503
            else:
                status = 404
            body = b"<html><body>Local baseline fixture</body></html>"
            self.send_response(status)
            for name, value in {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Content-Length": str(len(body)),
            }.items():
                self.send_header(name, value)
            if self.path == "/" and state["mode"] == "mixed_cookies":
                self.send_header("Set-Cookie", "protected=fixture; Path=/; Secure; HttpOnly; SameSite=Lax")
                self.send_header("Set-Cookie", "unprotected=fixture; Path=/")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("mode", ["normal", "failed_path", "mixed_cookies"])
def test_real_responses_preserve_evidence_through_report(
    target_server: tuple[str, dict[str, str]], mode: str,
) -> None:
    url, state = target_server
    state["mode"] = mode
    options = ScanOptions(
        check_https=False, check_ssl=False, check_dns_security=False,
        check_trace=False, check_info_leak=False,
        check_page_scan=True, check_page_cookie_flags=True,
        page_scan_max_pages=1, page_scan_max_depth=0,
    )
    result = scan(url, options=options)
    assert result.ok, result.error
    assert result.summary.scoring.enabled_count == 2
    assert result.checks["sensitive_paths"].value("paths") == []
    pages = result.checks["page_scan"]
    assert pages.value("pages_attempted") == pages.value("pages_scanned") == 1
    assert pages.value("pages_failed") == 0
    if mode == "failed_path":
        assert result.summary.score is None
        assert result.summary.level == "待完成"
        assert result.summary.scoring.unknown_count == 1
        assert result.checks["sensitive_paths"].value("failed_count") == 1
    else:
        assert result.summary.score == 100
        assert result.summary.level == "A级"
    findings = pages.findings
    assert len(findings) == (1 if mode == "mixed_cookies" else 0)
    if findings:
        assert findings[0].get("type") == "cookie_flags"
        assert "unprotected" in findings[0].get("message", "")
    view = build_result_view_model(result)
    assert view.overview.score == result.summary.score
    assert view.overview.scoring == result.summary.scoring
    summary = result.to_dict()["summary"]
    assert isinstance(summary, dict)
    assert summary["score"] == result.summary.score
    assert summary["scoring"] == result.summary.scoring.to_dict()

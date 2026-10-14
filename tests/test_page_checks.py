"""页面级安全检查规则的离线行为测试。"""

from types import SimpleNamespace
from typing import cast

import requests
import pytest
from requests.cookies import RequestsCookieJar, create_cookie

from scanner.pagecheck.page_checks import (
    PageParser,
    cookie_flag_state,
    cookie_security_findings,
    detect_exposed_info,
    is_same_origin,
    resolve_links,
)


def test_page_parser_collects_unique_links_resources_and_forms() -> None:
    """HTML 解析应收集链接、资源和表单，并保持资源去重。"""
    parser = PageParser()
    parser.feed(
        """
        <a href="/docs">Docs</a><a href="/docs">Again</a>
        <link href="/site.css"><script src="/app.js"></script>
        <img src="/logo.png" srcset="/logo.png 1x, /logo@2x.png 2x" data-src="/fallback.png">
        <form action="http://example.com/login" method="POST"></form>
        """
    )

    assert parser.links == ["/docs"]
    assert parser.resources == ["/site.css", "/app.js", "/logo.png", "/logo@2x.png", "/fallback.png"]
    assert parser.forms == [{"action": "http://example.com/login", "method": "post"}]


def test_page_helpers_filter_cross_origin_links_and_detect_cookie_source_risks() -> None:
    """页面辅助规则应拒绝跨源链接，并识别安全 Cookie 和源码暴露。"""
    resolved = resolve_links(
        "https://example.com/docs/",
        ["guide", "/security", "https://other.example/docs", "mailto:security@example.com"],
    )
    cookies = RequestsCookieJar()
    cookies.set_cookie(
        create_cookie("session", "value", secure=True, rest={"HttpOnly": None, "SameSite": "Lax"})
    )

    flags = cookie_flag_state(cast(requests.Response, SimpleNamespace(cookies=cookies)))
    matches, risk = detect_exposed_info("localhost 10.1.2.3 sourceMappingURL=app.js.map")

    assert resolved == ["https://example.com/docs/guide", "https://example.com/security"]
    assert flags == {"secure": True, "httponly": True, "samesite": True}
    assert risk == "中"
    assert any(item.startswith("loopback address:") for item in matches)
    assert any(item.startswith("source map:") for item in matches)


def test_cookie_attributes_must_belong_to_each_cookie_and_values_are_omitted() -> None:
    """安全 Cookie 的属性不能遮住同名但不同路径的不安全 Cookie。"""
    cookies = RequestsCookieJar()
    cookies.set_cookie(create_cookie(
        "session", "secret-safe", domain="example.com", path="/",
        secure=True, rest={"HttpOnly": None, "SameSite": "Lax"},
    ))
    cookies.set_cookie(create_cookie(
        "session", "secret-unsafe", domain="example.com", path="/admin",
        secure=False, rest={},
    ))
    response = cast(requests.Response, SimpleNamespace(cookies=cookies))

    findings = cookie_security_findings(response)

    assert findings == [{
        "name": "session", "domain": "example.com", "path": "/admin",
        "missing_flags": ["Secure", "HttpOnly", "SameSite"],
    }]
    assert cookie_flag_state(response) == {"secure": False, "httponly": False, "samesite": False}
    assert "secret-" not in str(findings)


@pytest.mark.parametrize("same_site", [None, "", "unexpected"])
def test_cookie_samesite_requires_a_valid_value(same_site: str | None) -> None:
    """只有属性名或未知取值不能作为有效 SameSite 证据。"""
    cookies = RequestsCookieJar()
    cookies.set_cookie(create_cookie(
        "session", "secret", secure=True, rest={"HttpOnly": None, "SameSite": same_site},
    ))
    response = cast(requests.Response, SimpleNamespace(cookies=cookies))

    assert cookie_security_findings(response)[0]["missing_flags"] == ["SameSite"]


def test_no_cookies_have_no_attribute_findings() -> None:
    """没有 Set-Cookie 的响应没有 Cookie 属性风险。"""
    response = cast(requests.Response, SimpleNamespace(cookies=RequestsCookieJar()))

    assert cookie_security_findings(response) == []
    assert all(cookie_flag_state(response).values())


@pytest.mark.parametrize(
    ("base", "candidate", "expected"),
    [
        ("https://EXAMPLE.com", "https://example.com/path", True),
        ("https://example.com:443", "https://example.com/", True),
        ("http://example.com", "http://example.com:80/path", True),
        ("https://example.com", "https://example.com:8443", False),
        ("https://example.com", "http://example.com", False),
        ("https://example.com", "https://other.example", False),
        ("https://example.com", "https://example.com:invalid", False),
    ],
)
def test_same_origin_compares_normalized_host_scheme_and_effective_port(base: str, candidate: str, expected: bool) -> None:
    assert is_same_origin(base, candidate) is expected

"""页面级安全检查规则的离线行为测试。"""

from types import SimpleNamespace
from typing import cast

import requests
from requests.cookies import RequestsCookieJar, create_cookie

from scanner.pagecheck.page_checks import (
    PageParser,
    cookie_flag_state,
    detect_exposed_info,
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

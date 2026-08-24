"""robots.txt 与 sitemap.xml 公开入口检查的离线行为测试。"""

from types import SimpleNamespace
from unittest.mock import patch

import requests

from scanner.pagecheck.sitecheck import scan_sitecheck
from scanner.pagecheck.sitecheck import crawl_policy, sitemap


def _response(*, status_code: int = 200, text: str = "", content_type: str = "text/plain") -> SimpleNamespace:
    """构造 sitecheck 所需的最小 HTTP 响应。"""
    return SimpleNamespace(
        status_code=status_code,
        text=text,
        content=text.encode("utf-8"),
        headers={"Content-Type": content_type},
    )


def test_crawl_policy_classifies_sensitive_paths_and_sitemap_references() -> None:
    """robots.txt 应保留规则，并识别管理入口和明文 sitemap。"""
    robots = """
    User-agent: *
    Disallow: /admin
    Disallow: /api-docs
    Sitemap: http://example.com/sitemap.xml
    """
    with patch.object(crawl_policy, "http_request", return_value=_response(text=robots)):
        result = crawl_policy.scan_crawl_policy(requests.Session(), "https://example.com")

    assert result["status"] == "ok"
    assert result["disallow_paths"] == ["/admin", "/api-docs"]
    assert result["sitemap_urls"] == ["http://example.com/sitemap.xml"]
    assert {(item["risk"], item["type"]) for item in result["findings"]} == {
        ("高", "管理入口"),
        ("中", "接口文档或管理端点"),
        ("中", "明文 Sitemap"),
    }


def test_sitecheck_aggregates_robots_and_sitemap_findings() -> None:
    """统一 sitecheck 应聚合 robots 和 sitemap 风险、状态及页面入口。"""
    robots = "Disallow: /admin\nSitemap: https://example.com/sitemap.xml"
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/public</loc></url>
      <url><loc>http://example.com/legacy</loc></url>
    </urlset>"""

    def request(_session: requests.Session, _method: str, url: str, **_kwargs: object) -> SimpleNamespace:
        if url.endswith("/robots.txt"):
            return _response(text=robots)
        if url.endswith("/sitemap.xml"):
            return _response(text=sitemap_xml, content_type="application/xml")
        raise AssertionError(f"unexpected request: {url}")

    with (
        patch.object(crawl_policy, "http_request", side_effect=request),
        patch.object(sitemap, "http_request", side_effect=request),
    ):
        result = scan_sitecheck(requests.Session(), "https://example.com")

    assert result["status"] == "ok"
    assert result["seed_urls"] == ["https://example.com/public", "http://example.com/legacy"]
    assert result["finding_count"] == 3
    assert result["risk_counts"] == {"低": 1, "中": 1, "高": 1}
    assert result["highest_risk"] == "高"

"""扫描结果构造与 Result → ViewModel 转换。"""

from collections.abc import Iterable, Mapping
from typing import cast

from .models import (
    AvailabilityViewData,
    CertificateViewData,
    CipherViewData,
    CrawlPolicyViewData,
    DnsRecordViewData,
    DnsViewData,
    Finding,
    FindingView,
    HttpMethodsViewData,
    InfoLeakViewData,
    JsonObject,
    JsonValue,
    Messages,
    OverviewViewModel,
    PageScanSummaryData,
    PageScanViewData,
    RedirectIssueViewData,
    ResultSections,
    ScanResult,
    ScanViewModel,
    SectionView,
    SectionResult,
    SectionStatus,
    SecurityHeadersViewData,
    SiteCheckViewData,
    SitemapViewData,
    Summary,
    TargetResult,
    TlsViewData,
    finding_view,
)


def build_target_result(
    input_url: str,
    normalized_url: str,
    host: str,
    resolved_ips: list[str],
) -> TargetResult:
    """构造目标信息结果。"""

    return TargetResult(
        input_url=input_url,
        normalized_url=normalized_url,
        url=normalized_url,
        host=host,
        resolved_ips=list(resolved_ips),
    )


def wrap_section_result(
    name: str,
    payload: Mapping[str, object] | None = None,
    *,
    enabled: bool | None = None,
    status: SectionStatus = SectionStatus.OK,
    summary: str = "",
    warnings: Iterable[str] | None = None,
    findings: Iterable[Mapping[str, object]] | None = None,
) -> SectionResult:
    """把模块原始结果包装成统一 section 模型。"""

    data = cast(JsonObject, dict(payload or {}))
    raw_meta = data.pop("meta", {})
    raw_warnings = data.pop("warnings", [])
    raw_findings = data.pop("findings", [])

    return SectionResult(
        name=name,
        enabled=enabled,
        status=status,
        summary=summary,
        meta=_as_json_object(raw_meta),
        warnings=list(warnings) if warnings is not None else _as_text_list(raw_warnings),
        findings=(
            _as_findings(findings)
            if findings is not None
            else _as_findings(raw_findings)
        ),
        data=data,
    )


def get_section(result: ScanResult, name: str) -> SectionResult | None:
    """从统一扫描结果中读取 section。"""

    return result.checks.get(name)


def build_result_view_model(result: ScanResult) -> ScanViewModel:
    """把扫描结果转换成展示层使用的稳定 ViewModel。"""

    sections = _build_result_sections(result)
    return ScanViewModel(
        overview=OverviewViewModel(
            score=result.summary.score if result.summary.score is not None else 0,
            level=result.summary.level,
            elapsed_seconds=result.summary.elapsed_seconds,
            https=sections.https,
            page_scan=sections.page_scan.data,
        ),
        target=result.target,
        sections=sections,
        messages=result.messages,
        raw=result.to_dict(),
    )


def _build_result_sections(result: ScanResult) -> ResultSections:
    """把原始 section payload 一次性转换为展示层 typed sections。"""
    availability = _section(result, "availability")
    https = _section(result, "https")
    tls = _section(result, "tls")
    dns = _section(result, "dns_security")
    headers = _section(result, "security_headers")
    methods = _section(result, "http_methods")
    paths = _section(result, "sensitive_paths")
    info_leak = _section(result, "info_leak")
    page_scan = _section(result, "page_scan")

    return ResultSections(
        availability=SectionView(availability, _availability_data(availability)),
        https=SectionView(https, _bool_value(https.value("value"))),
        tls=SectionView(tls, _tls_data(tls)),
        dns_security=SectionView(dns, _dns_data(dns)),
        security_headers=SectionView(headers, _security_headers_data(headers)),
        http_methods=SectionView(methods, _http_methods_data(methods)),
        sensitive_paths=SectionView(paths, _text_list_value(paths.value("paths"))),
        info_leak=SectionView(info_leak, _info_leak_data(info_leak)),
        page_scan=SectionView(page_scan, _page_scan_data(page_scan)),
    )


def _section(result: ScanResult, name: str) -> SectionResult:
    """读取 section，不存在时返回稳定的禁用占位。"""
    return result.checks.get(name, SectionResult(name=name))


def _availability_data(section: SectionResult) -> AvailabilityViewData:
    """转换网站可用性 section。"""
    return AvailabilityViewData(
        dns_seconds=_float_value(section.value("dns_seconds")),
        tcp_connect_seconds=_float_value(section.value("tcp_connect_seconds")),
        tls_handshake_seconds=_float_value(section.value("tls_handshake_seconds")),
        ttfb_seconds=_float_value(section.value("ttfb_seconds")),
        total_bytes=_int_value(section.value("total_bytes")),
    )


def _tls_data(section: SectionResult) -> TlsViewData:
    """转换 TLS section。"""
    cipher = _object_value(section.value("cipher"))
    certificate = _object_value(section.value("certificate"))
    return TlsViewData(
        ssl_valid=_bool_value(section.value("ssl_valid")),
        ssl_days_left=_int_value(section.value("ssl_days_left")),
        protocol=_text_value(section.value("protocol")),
        cipher=CipherViewData(
            cipher_name=_text_value(cipher.get("cipher_name")),
            cipher_bits=_int_value(cipher.get("cipher_bits"), 0) or 0,
        ),
        certificate=CertificateViewData(
            subject=_text_value(certificate.get("subject")),
            issuer=_text_value(certificate.get("issuer")),
            not_before=_text_value(certificate.get("not_before")),
            not_after=_text_value(certificate.get("not_after")),
            serial_number=_text_value(certificate.get("serial_number")),
        ),
        supported_protocols=_text_list_value(section.value("supported_protocols")),
        weak_protocols=_text_list_value(section.value("weak_protocols")),
        chain_length=_int_value(section.value("chain_length")),
        chain_complete=_bool_value(section.value("chain_complete")),
        cipher_weak=_bool_value(section.value("cipher_weak")),
    )


def _dns_data(section: SectionResult) -> DnsViewData:
    """转换 DNS section。"""
    return DnsViewData(
        domain=_text_value(section.value("domain")),
        lookup_domain=_text_value(section.value("lookup_domain")),
        spf=_dns_record_data(section.value("spf")),
        dmarc=_dns_record_data(section.value("dmarc")),
        caa=_dns_record_data(section.value("caa")),
    )


def _dns_record_data(value: JsonValue) -> DnsRecordViewData:
    """转换单类 DNS 记录。"""
    data = _object_value(value)
    return DnsRecordViewData(
        present=_bool_value(data.get("present")),
        records=_text_list_value(data.get("records")),
        policy=_optional_text_value(data.get("policy")),
        issuers=_text_list_value(data.get("issuers")),
    )


def _security_headers_data(section: SectionResult) -> SecurityHeadersViewData:
    """转换安全响应头 section。"""
    return SecurityHeadersViewData(
        score=_int_value(section.value("score")),
        missing=_text_list_value(section.value("missing")),
    )


def _http_methods_data(section: SectionResult) -> HttpMethodsViewData:
    """转换 HTTP 方法 section。"""
    return HttpMethodsViewData(
        options_status=_int_value(section.value("options_status")),
        allow_methods=_text_list_value(section.value("allow_methods")),
        cors_methods=_text_list_value(section.value("cors_methods")),
        exposed_methods=_text_list_value(section.value("exposed_methods")),
        trace_enabled=_bool_value(section.value("trace_enabled")),
    )


def _info_leak_data(section: SectionResult) -> InfoLeakViewData:
    """转换暴露信息 section。"""
    return InfoLeakViewData(
        version_exposed=_bool_value(section.value("version_exposed")),
        framework_exposed=_bool_value(section.value("framework_exposed")),
        meta_exposed=_bool_value(section.value("meta_exposed")),
        header_findings=_finding_views(section.value("header_findings")),
        meta_fields=_finding_views(section.value("meta_fields")),
    )


def _page_scan_data(section: SectionResult) -> PageScanViewData:
    """转换页面扫描 section。"""
    return PageScanViewData(
        enabled=section.enabled is True,
        pages_scanned=_int_value(section.value("pages_scanned"), 0) or 0,
        max_pages=_int_value(section.value("max_pages"), 0) or 0,
        max_depth=_int_value(section.value("max_depth"), 0) or 0,
        finding_count=_int_value(section.value("finding_count"), 0) or 0,
        highest_risk=_text_value(section.value("highest_risk"), "无"),
        risk_counts=_int_mapping(section.value("risk_counts")),
        message=_text_value(section.value("message")),
        sitecheck=_sitecheck_data(section.value("sitecheck")),
        redirect_issues=_redirect_issues(section.value("redirect_issues")),
    )


def _sitecheck_data(value: JsonValue) -> SiteCheckViewData | None:
    """转换 robots/sitemap 汇总 section。"""
    data = _object_value(value)
    if not data:
        return None
    return SiteCheckViewData(
        enabled=_bool_value(data.get("enabled")) is True,
        status=_text_value(data.get("status"), "未知"),
        robots_url=_text_value(data.get("robots_url")),
        sitemap_url_count=_int_value(data.get("sitemap_url_count"), 0) or 0,
        finding_count=_int_value(data.get("finding_count"), 0) or 0,
        seed_url_count=_int_value(data.get("seed_url_count"), 0) or 0,
        highest_risk=_text_value(data.get("highest_risk"), "无"),
        risk_counts=_int_mapping(data.get("risk_counts")),
        crawl_policy=_crawl_policy_data(data.get("crawl_policy")),
        sitemap=_sitemap_data(data.get("sitemap")),
    )


def _crawl_policy_data(value: JsonValue) -> CrawlPolicyViewData:
    """转换 robots.txt 数据。"""
    data = _object_value(value)
    return CrawlPolicyViewData(
        status=_text_value(data.get("status"), "未知"),
        robots_url=_text_value(data.get("robots_url")),
        allow_paths=_text_list_value(data.get("allow_paths")),
        disallow_paths=_text_list_value(data.get("disallow_paths")),
        sitemap_urls=_text_list_value(data.get("sitemap_urls")),
        findings=_finding_views(data.get("findings")),
        warnings=_text_list_value(data.get("warnings")),
    )


def _sitemap_data(value: JsonValue) -> SitemapViewData:
    """转换 sitemap.xml 数据。"""
    data = _object_value(value)
    return SitemapViewData(
        status=_text_value(data.get("status"), "未知"),
        sitemap_count=_int_value(data.get("sitemap_count"), 0) or 0,
        url_count=_int_value(data.get("url_count"), 0) or 0,
        candidate_urls=_text_list_value(data.get("candidate_urls")),
        candidate_url_count=_int_value(data.get("candidate_url_count")),
        candidate_urls_truncated=_bool_value(data.get("candidate_urls_truncated")) is True,
        seed_urls=_text_list_value(data.get("seed_urls")),
        seed_url_count=_int_value(data.get("seed_url_count")),
        seed_urls_truncated=_bool_value(data.get("seed_urls_truncated")) is True,
        findings=_finding_views(data.get("findings")),
        finding_count=_int_value(data.get("finding_count")),
        findings_truncated=_bool_value(data.get("findings_truncated")) is True,
        warnings=_text_list_value(data.get("warnings")),
    )


def _redirect_issues(value: JsonValue) -> list[RedirectIssueViewData]:
    """转换页面重定向记录。"""
    if not isinstance(value, list):
        return []
    result: list[RedirectIssueViewData] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        result.append(
            RedirectIssueViewData(
                status_code=_int_value(item.get("status_code"), 0) or 0,
                source=_text_value(item.get("from")),
                target=_text_value(item.get("to")),
            )
        )
    return result


def _finding_views(value: JsonValue) -> list[FindingView]:
    """转换 JSON 发现项列表。"""
    if not isinstance(value, list):
        return []
    result: list[FindingView] = []
    for item in value:
        if isinstance(item, dict):
            result.append(finding_view(cast(Finding, item)))
    return result


def _object_value(value: JsonValue) -> dict[str, JsonValue]:
    """把 JSON 值收窄为对象。"""
    return value if isinstance(value, dict) else {}


def _text_value(value: JsonValue, default: str = "") -> str:
    """读取 JSON 字符串。"""
    return value if isinstance(value, str) else default


def _optional_text_value(value: JsonValue) -> str | None:
    """读取可空 JSON 字符串。"""
    return value if isinstance(value, str) else None


def _bool_value(value: JsonValue) -> bool | None:
    """读取可空 JSON 布尔值。"""
    return value if isinstance(value, bool) else None


def _int_value(value: JsonValue, default: int | None = None) -> int | None:
    """读取可空 JSON 整数。"""
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _float_value(value: JsonValue) -> float | None:
    """读取可空 JSON 浮点数。"""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _text_list_value(value: JsonValue) -> list[str]:
    """读取 JSON 字符串列表。"""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _int_mapping(value: JsonValue) -> dict[str, int]:
    """读取 JSON 整数映射。"""
    if not isinstance(value, dict):
        return {}
    return {
        str(key): item
        for key, item in value.items()
        if isinstance(item, int) and not isinstance(item, bool)
    }


def summarize_page_scan(page_scan: SectionResult | None) -> PageScanSummaryData:
    """把页面扫描 section 压缩成概览。"""

    if page_scan is None:
        return _empty_page_scan_summary()

    risk_counts = _as_int_mapping(page_scan.value("risk_counts"))
    return {
        "enabled": _as_bool(page_scan.value("enabled"), False),
        "pages_scanned": _as_int(page_scan.value("pages_scanned"), 0),
        "finding_count": _as_int(page_scan.value("finding_count"), 0),
        "risk_counts": risk_counts or {"低": 0, "中": 0, "高": 0},
        "highest_risk": _as_text(page_scan.value("highest_risk"), "无"),
    }


def compose_scan_result(
    *,
    target: TargetResult,
    checks: Mapping[str, SectionResult],
    score: int,
    level: str,
    elapsed_seconds: float,
    page_scan: SectionResult | None = None,
    errors: Iterable[str] | None = None,
    warnings: Iterable[str] | None = None,
) -> ScanResult:
    """合成最终的大结果。"""

    error_list = _unique_texts(errors or [])
    warning_list = _unique_texts(warnings or [])
    warning_list.extend(_collect_section_warnings(checks))
    warning_list = _unique_texts(warning_list)
    return ScanResult(
        ok=True,
        target=target,
        checks=dict(checks),
        summary=Summary(
            score=score,
            level=level,
            elapsed_seconds=elapsed_seconds,
            page_scan_summary=summarize_page_scan(page_scan),
        ),
        messages=Messages(errors=error_list, warnings=warning_list),
    )


def compose_scan_error(message: str, elapsed_seconds: float) -> ScanResult:
    """构造统一的扫描失败结果。"""

    return ScanResult(
        ok=False,
        summary=Summary(elapsed_seconds=elapsed_seconds),
        messages=Messages(errors=[message]),
        error=message,
    )


def _unique_texts(values: Iterable[object]) -> list[str]:
    """对字符串列表去重并保持顺序。"""

    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _collect_section_warnings(checks: Mapping[str, SectionResult]) -> list[str]:
    """聚合各 section 的 warning。"""

    warnings: list[str] = []
    for section in checks.values():
        warnings.extend(section.warnings)
    return _unique_texts(warnings)


def _empty_page_scan_summary() -> PageScanSummaryData:
    """返回未启用页面扫描时使用的默认概览。"""
    return {
        "enabled": False,
        "pages_scanned": 0,
        "finding_count": 0,
        "risk_counts": {"低": 0, "中": 0, "高": 0},
        "highest_risk": "无",
    }


def _as_json_object(value: object) -> JsonObject:
    """将外部值收窄为 JSON 对象。"""
    return cast(JsonObject, value) if isinstance(value, Mapping) else {}


def _as_findings(value: Iterable[Mapping[str, object]] | object) -> list[Finding]:
    """将外部发现项列表转换为统一发现项类型。"""
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return []
    items = cast(Iterable[object], value)
    findings: list[Finding] = []
    for item in items:
        if isinstance(item, Mapping):
            mapping = cast(Mapping[str, object], item)
            findings.append(cast(Finding, dict(mapping)))
    return findings


def _as_text_list(value: object) -> list[str]:
    """将外部可迭代值转换为文本列表。"""
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return []
    items = cast(Iterable[object], value)
    return [str(item) for item in items]


def _as_bool(value: JsonValue, default: bool) -> bool:
    """读取布尔 JSON 值，类型不匹配时返回默认值。"""
    return value if isinstance(value, bool) else default


def _as_int(value: JsonValue, default: int) -> int:
    """读取整数 JSON 值，类型不匹配时返回默认值。"""
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _as_text(value: JsonValue, default: str) -> str:
    """读取字符串 JSON 值，类型不匹配时返回默认值。"""
    return value if isinstance(value, str) else default


def _as_int_mapping(value: JsonValue) -> dict[str, int]:
    """将 JSON 对象中的整数项提取为计数字典。"""
    if not isinstance(value, Mapping):
        return {}
    return {
        str(key): item
        for key, item in value.items()
        if isinstance(item, int) and not isinstance(item, bool)
    }

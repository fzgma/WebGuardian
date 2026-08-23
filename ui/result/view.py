import ipaddress
import re
from collections.abc import Sequence
from typing import Any

import streamlit as st

from ui.result.composer import build_result_view_model
from ui.result.models import (
    AvailabilityViewData,
    DnsRecordViewData,
    DnsViewData,
    FindingView,
    HttpMethodsViewData,
    InfoLeakViewData,
    PageScanViewData,
    ScanResult,
    SectionStatus,
    SectionView,
    SiteCheckViewData,
    TlsViewData,
)


def render_scan_result(result: ScanResult) -> None:
    """渲染扫描结果。"""
    view_model = build_result_view_model(result)
    overview = view_model.overview
    target = view_model.target
    sections = view_model.sections
    messages = view_model.messages
    https_check = sections.https
    availability_check = sections.availability
    tls_check = sections.tls
    dns_check = sections.dns_security
    headers_check = sections.security_headers
    methods_check = sections.http_methods
    paths_check = sections.sensitive_paths
    info_leak = sections.info_leak
    page_scan = sections.page_scan

    st.subheader("检测结果概览")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("安全评分", f"{overview.score}/100")
    col2.metric("安全等级", overview.level)
    https_label = _format_https_label(https_check, tls_check)
    col3.metric("HTTPS", https_label)
    elapsed_seconds = overview.elapsed_seconds
    col4.metric("检测耗时", _format_elapsed_seconds(elapsed_seconds))

    page_summary = overview.page_scan
    if page_summary["enabled"]:
        risk_counts = page_summary["risk_counts"]
        st.caption(
            f"页面扫描：已检查 {page_summary['pages_scanned']} 页，"
            f"发现 {page_summary['finding_count']} 个问题，"
            f"高 {risk_counts.get('高', 0)} / 中 {risk_counts.get('中', 0)} / 低 {risk_counts.get('低', 0)}，"
            f"最高风险 {page_summary['highest_risk']}"
        )

    st.divider()
    st.subheader("基础信息")
    st.write("检测地址：", target.url)
    st.write("主机名称：", target.host)
    resolved_ips = target.resolved_ips
    if resolved_ips:
        # 摘要只保留一个 IPv4 和一个 IPv6。
        ipv4, ipv6 = _split_resolved_ips(resolved_ips)
        summary_ips = [ip for ip in (ipv4, ipv6) if ip]
        st.write("解析到的 IP：", "，".join(summary_ips))
        with st.expander("查看完整 IP 列表"):
            ipv4_list, ipv6_list = _group_resolved_ips(resolved_ips)
            if ipv4_list and ipv6_list:
                col_v4, col_v6 = st.columns(2)
                with col_v4:
                    st.caption("IPv4")
                    st.table([{"IP": ip} for ip in ipv4_list])
                with col_v6:
                    st.caption("IPv6")
                    st.table([{"IP": ip} for ip in ipv6_list])
            else:
                # 只有一种地址族时，保持单栏列表。
                st.table([{"IP": ip} for ip in resolved_ips])


    _render_availability(availability_check)

    st.divider()
    st.subheader("TLS/SSL 检测")
    if tls_check.enabled is not True:
        st.info("SSL 检测已关闭。")
    else:
        ssl_valid = tls_check.data.ssl_valid
        st.write("SSL 证书有效：", "是" if ssl_valid else "否")

    if tls_check.data.ssl_valid:
        st.write("证书剩余天数：", tls_check.data.ssl_days_left)
    elif tls_check.data.ssl_valid is False:
        st.warning("未检测到有效的 SSL 证书，或证书检测失败。")

    _render_tls_details(tls_check)

    st.divider()
    _render_dns_security(dns_check)

    st.divider()
    st.subheader("HTTP 安全头检测")
    if headers_check.enabled is not True:
        st.info("安全响应头检测已关闭。")
    else:
        st.write("安全头得分：", headers_check.data.score)

    missing_headers = headers_check.data.missing
    if missing_headers:
        st.warning("存在缺失的安全响应头：")
        st.code("\n".join(missing_headers))
    elif headers_check.enabled is True:
        st.success("未发现缺失的安全响应头。")

    st.divider()
    _render_http_methods(methods_check)

    st.divider()
    st.subheader("敏感路径检测")
    sensitive_paths = paths_check.data
    if paths_check.enabled is not True:
        st.info("敏感路径检测已关闭。")
    elif sensitive_paths:
        st.warning("发现可能存在的敏感路径：")
        st.code("\n".join(sensitive_paths))
    else:
        st.success("未发现常见敏感路径。")

    st.divider()
    st.subheader("暴露信息检测")
    _render_exposure_status(
        info_leak.data.version_exposed,
        "响应头中存在可识别的服务器版本特征。",
        "未发现明显的服务器版本特征。",
        "服务器版本特征未检测。",
    )
    _render_exposure_status(
        info_leak.data.framework_exposed,
        "响应头中存在可识别的框架特征。",
        "未发现明显的框架特征。",
        "框架特征未检测。",
    )
    _render_exposure_status(
        info_leak.data.meta_exposed,
        "页面源码中存在可识别的重点 meta 字段。",
        "未发现明显的重点 meta 字段。",
        "重点 meta 字段未检测。",
    )
    _render_info_leak_details(info_leak)

    _render_page_scan(page_scan)
    st.divider()
    _render_sitecheck(page_scan.data.sitecheck)
    _render_messages(messages.errors, messages.warnings)

    st.divider()
    with st.expander("查看原始检测结果"):
        st.json(view_model.raw)


def _render_exposure_status(
    exposed: bool | None, warning: str, success: str, disabled: str
) -> None:
    """展示暴露信息检测状态。"""
    if exposed is True:
        st.warning(warning)
    elif exposed is False:
        st.success(success)
    else:
        st.info(disabled)


def _format_https_label(https_check: SectionView[bool | None], tls_check: SectionView[TlsViewData]) -> str:
    """根据 HTTPS 或 TLS 结果显示概览中的 HTTPS 状态。"""
    if https_check.enabled is True:
        return "是" if https_check.data is True else "否"

    if tls_check.enabled is True:
        ssl_valid = tls_check.data.ssl_valid
        if ssl_valid is True:
            return "是"
        if ssl_valid is False:
            return "否"

    return "未检测"


def _render_availability(availability: SectionView[AvailabilityViewData] | None) -> None:
    """展示本次扫描的基础可用性指标。"""
    with st.expander("网站可用性", expanded=False):
        if not availability or availability.enabled is not True:
            st.info("网站可用性数据未记录。")
            return

        st.caption("仅展示本次正式请求的基础响应情况。")

        col1, col2, col3 = st.columns(3)
        col1.metric("DNS 解析", _format_duration_ms(availability.data.dns_seconds))
        col2.metric(
            "TCP 连接耗时",
            _format_duration_ms(availability.data.tcp_connect_seconds),
        )
        col3.metric(
            "TLS 握手耗时",
            _format_duration_ms(availability.data.tls_handshake_seconds),
        )

        col4, col5 = st.columns(2)
        col4.metric("TTFB", _format_duration_ms(availability.data.ttfb_seconds))
        col5.metric("发送/接收总量", _format_kb(availability.data.total_bytes))


def _render_http_methods(method_info: SectionView[HttpMethodsViewData] | None) -> None:
    """展示 HTTP 方法检测结果。"""
    st.subheader("HTTP 方法检测")
    if not method_info or method_info.enabled is not True:
        st.info("HTTP 方法检测已关闭。")
        return

    st.write(f"OPTIONS 响应状态：{_format_http_status(method_info.data.options_status)}")
    allow_methods = method_info.data.allow_methods
    cors_methods = method_info.data.cors_methods
    if allow_methods:
        st.caption(f"Allow：{', '.join(allow_methods)}")
    if cors_methods:
        st.caption(f"Access-Control-Allow-Methods：{', '.join(cors_methods)}")

    for warning in method_info.warnings:
        st.info(warning)

    exposed_methods = method_info.data.exposed_methods
    if method_info.data.trace_enabled is True:
        st.error("TRACE 方法已启用，存在一定安全风险。")
        if exposed_methods:
            st.warning(f"同时发现可能暴露的其他 HTTP 方法：{', '.join(exposed_methods)}")
    elif exposed_methods:
        st.warning(f"发现可能暴露的 HTTP 方法：{', '.join(exposed_methods)}")
    elif method_info.data.trace_enabled is False:
        st.success("未发现明显的 HTTP 方法暴露。")
    else:
        st.info("HTTP 方法检测结果不完整。")


def _render_dns_security(dns_security: SectionView[DnsViewData] | None) -> None:
    """展示 DNS 安全检测结果。"""
    st.subheader("DNS 安全检测")
    if not dns_security or dns_security.enabled is not True:
        st.info("DNS 安全检测已关闭。")
        return

    status = dns_security.status
    domain = dns_security.data.domain
    lookup_domain = dns_security.data.lookup_domain
    if status is SectionStatus.SKIPPED:
        st.info("DNS 安全检测已跳过。")
        for warning in dns_security.warnings:
            st.caption(warning)
        return

    if status is SectionStatus.ERROR:
        st.warning("DNS 安全检测执行异常，结果可能不完整。")

    st.write(f"检测域名：{domain}")
    if lookup_domain and lookup_domain != domain:
        st.caption(f"实际查询域名：{lookup_domain}")

    _render_dns_record_block("SPF", dns_security.data.spf)
    _render_dns_record_block("DMARC", dns_security.data.dmarc)
    _render_dns_record_block("CAA", dns_security.data.caa)

    findings = dns_security.findings
    if findings:
        _render_ranked_findings("DNS 安全检测问题", findings)
    elif status is not SectionStatus.ERROR:
        st.success("未发现明显的 DNS 安全问题。")

    for warning in dns_security.warnings:
        st.info(warning)


def _render_tls_details(tls_info: SectionView[TlsViewData] | None) -> None:
    """展示 TLS 配置详情。"""
    if not tls_info or tls_info.enabled is not True:
        return

    if tls_info.warnings:
        for warning in tls_info.warnings:
            st.warning(warning)

    protocol = tls_info.data.protocol
    cipher = tls_info.data.cipher
    certificate = tls_info.data.certificate
    supported_protocols = tls_info.data.supported_protocols
    weak_protocols = tls_info.data.weak_protocols
    chain_complete = tls_info.data.chain_complete
    chain_length = tls_info.data.chain_length

    if protocol:
        st.caption(f"协商协议：{protocol}")
    if cipher.cipher_name:
        st.caption(f"加密套件：{cipher.cipher_name} / {cipher.cipher_bits} bits")
    subject_text = _format_tls_dn_summary(certificate.subject)
    issuer_text = _format_tls_dn_summary(certificate.issuer)
    if subject_text:
        st.caption(f"证书主体：{subject_text}")
    if issuer_text:
        st.caption(f"签发机构：{issuer_text}")

    with st.expander("查看 TLS 详细信息"):
        if certificate:
            st.caption("证书信息")
            for label, value in (
                ("生效时间", certificate.not_before),
                ("过期时间", certificate.not_after),
                ("序列号", certificate.serial_number),
            ):
                if value:
                    st.write(f"{label}：{value}")

        if supported_protocols:
            st.caption(f"支持的协议：{', '.join(supported_protocols)}")
        if weak_protocols:
            st.warning(f"检测到弱协议：{', '.join(weak_protocols)}")
        if chain_length is not None:
            st.write(f"证书链长度：{chain_length}")
        if chain_complete is True:
            st.success("证书链看起来是完整的。")
        elif chain_complete is False:
            st.warning("证书链可能不完整。")
        if tls_info.data.cipher_weak is True:
            st.warning("当前协商的加密套件偏弱。")
        elif tls_info.data.cipher_weak is False:
            st.success("当前协商的加密套件看起来正常。")


def _render_dns_record_block(label: str, data: DnsRecordViewData) -> None:
    """展示单类 DNS 记录摘要。"""
    if not data.records and data.present is None and not data.issuers:
        return

    summary = "已发现" if data.present else "未发现"
    if data.policy:
        summary = f"{summary}，策略：{data.policy}"
    st.caption(f"{label}：{summary}")
    if data.records:
        with st.expander(f"查看 {label} 记录"):
            st.code("\n".join(data.records))
    if label == "CAA" and data.issuers:
        st.caption(f"允许签发来源：{', '.join(data.issuers)}")


def _render_info_leak_details(info_leak: SectionView[InfoLeakViewData]) -> None:
    """展示响应头和 meta 的细节暴露项。"""
    header_findings = info_leak.data.header_findings
    meta_fields = info_leak.data.meta_fields
    if not header_findings and not meta_fields:
        return

    with st.expander("查看暴露详情"):
        if header_findings:
            st.caption("响应头暴露")
            for finding in header_findings:
                st.write(f"- {finding.field or '响应头'}: {finding.value}")
                st.caption(f"说明：{finding.message}")
                st.caption(f"建议：{finding.suggestion}")

        if meta_fields:
            st.caption("页面源码 meta")
            for finding in meta_fields:
                st.write(f"- {finding.field or 'meta'}: {finding.value}")
                st.caption(f"说明：{finding.message}")
                st.caption(f"建议：{finding.suggestion}")


def _format_http_status(status: Any) -> str:
    """把 HTTP 状态码格式化成可读文案。"""
    if status is None:
        return "未知"

    try:
        code = int(status)
    except (TypeError, ValueError):
        return str(status)

    descriptions = {
        200: "200（请求成功）",
        204: "204（无内容）",
        301: "301（永久重定向）",
        302: "302（临时重定向）",
        401: "401（未认证）",
        403: "403（禁止访问）",
        405: "405（不允许此方法）",
        500: "500（服务器内部错误）",
    }
    return descriptions.get(code, f"{code}")


def _format_elapsed_seconds(value: Any) -> str:
    """把耗时格式化为秒。"""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "未知"
    if seconds < 0:
        return "未知"
    return f"{seconds:.2f} 秒"


def _format_duration_ms(value: Any) -> str:
    """把秒格式化成毫秒。"""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "N/A"
    if seconds < 0:
        return "N/A"
    return f"{seconds * 1000:.0f} ms"


def _format_kb(value: Any) -> str:
    """把字节数格式化成 KB。"""
    try:
        bytes_value = float(value)
    except (TypeError, ValueError):
        return "N/A"
    if bytes_value < 0:
        return "N/A"

    kb = bytes_value / 1024
    if kb < 10:
        return f"{kb:.1f} KB"
    return f"{kb:.0f} KB"


def _format_tls_dn_summary(value: Any) -> str:
    """把证书 DN 压缩成国家和机构名摘要。"""
    text = str(value or "").strip()
    if not text:
        return ""

    country = _extract_dn_value(text, "countryName")
    organization = _extract_dn_value(text, "organizationName")

    parts: list[str] = []
    if country:
        parts.append(f"国家：{country.lower()}")
    if organization:
        parts.append(f"机构名：{organization}")
    return "，".join(parts)


def _extract_dn_value(text: str, field: str) -> str:
    """从逗号分隔的 DN 文本中取出单字段值。"""
    match = re.search(rf"(?:^|,\s*){re.escape(field)}=([^,]+)", text)
    if not match:
        return ""
    return match.group(1).strip()


def _render_sitecheck(sitecheck: SiteCheckViewData | None) -> None:
    """展示 robots.txt / sitemap.xml 暴露面分析。"""
    st.subheader("robots.txt / sitemap.xml 暴露面分析")
    if not sitecheck or not sitecheck.enabled:
        st.info("robots.txt / sitemap.xml 暴露面分析未启用。")
        return

    crawl_policy = sitecheck.crawl_policy
    sitemap = sitecheck.sitemap
    risk_counts = sitecheck.risk_counts
    st.write(
        f"状态：{sitecheck.status}，"
        f"robots 声明 {sitecheck.sitemap_url_count} 个 sitemap，"
        f"发现项 {sitecheck.finding_count} 个，"
        f"高 {risk_counts.get('高', 0)} / 中 {risk_counts.get('中', 0)} / 低 {risk_counts.get('低', 0)}，"
        f"可继续分析入口 {sitecheck.seed_url_count} 个，"
        f"最高风险 {sitecheck.highest_risk}"
    )
    st.caption(f"robots.txt：{sitecheck.robots_url or crawl_policy.robots_url}")

    with st.expander("查看 robots.txt 详情"):
        st.write(f"robots.txt 状态：{crawl_policy.status}")
        _render_limited_text_list("Allow 规则", crawl_policy.allow_paths)
        _render_limited_text_list("Disallow 规则", crawl_policy.disallow_paths)
        _render_limited_text_list("Sitemap 声明", crawl_policy.sitemap_urls)
        _render_ranked_findings("robots.txt 问题", crawl_policy.findings)
        for warning in crawl_policy.warnings:
            st.info(warning)

    with st.expander("查看 sitemap.xml 详情"):
        st.write(f"sitemap 状态：{sitemap.status}")
        st.write(
            f"子 sitemap {sitemap.sitemap_count} 个，"
            f"页面入口 {sitemap.url_count} 个"
        )
        _render_limited_text_list(
            "候选 sitemap",
            sitemap.candidate_urls,
            total_count=sitemap.candidate_url_count,
            truncated=sitemap.candidate_urls_truncated,
        )
        _render_limited_text_list(
            "可继续分析的页面入口",
            sitemap.seed_urls,
            total_count=sitemap.seed_url_count,
            truncated=sitemap.seed_urls_truncated,
        )
        _render_ranked_findings(
            "sitemap.xml 问题",
            sitemap.findings,
            total_count=sitemap.finding_count,
            truncated=sitemap.findings_truncated,
        )
        for warning in sitemap.warnings:
            st.info(warning)


def _render_ranked_findings(
    section_label: str,
    findings: Sequence[FindingView],
    *,
    total_count: int | None = None,
    truncated: bool = False,
) -> None:
    """按风险等级展示发现。"""
    if not findings:
        st.success(f"未发现明显的 {section_label}。")
        return

    grouped = _group_findings_by_risk(findings)
    st.caption(f"高 {len(grouped['高'])} 个，中 {len(grouped['中'])} 个，低 {len(grouped['低'])} 个")

    if grouped["高"]:
        st.subheader("高风险结果")
        for idx, finding in enumerate(grouped["高"], start=1):
            _render_finding_item(idx, finding)

    if grouped["中"]:
        with st.expander("显示等级为中的结果"):
            for idx, finding in enumerate(grouped["中"], start=1):
                _render_finding_item(idx, finding)

    if grouped["低"]:
        with st.expander("显示等级为低的结果"):
            for idx, finding in enumerate(grouped["低"], start=1):
                _render_finding_item(idx, finding)

    if truncated and total_count is not None and total_count > len(findings):
        st.info(f"仅展示前 {len(findings)} 条发现，共 {total_count} 条。")


def _group_findings_by_risk(findings: Sequence[FindingView]) -> dict[str, list[FindingView]]:
    """按风险等级分组发现。"""
    grouped: dict[str, list[FindingView]] = {"高": [], "中": [], "低": []}
    for finding in findings:
        risk = finding.risk
        if risk not in grouped:
            continue
        grouped[risk].append(finding)
    return grouped


def _render_finding_item(idx: int, finding: FindingView) -> None:
    """渲染单条发现。"""
    st.write(f"{idx}. [{finding.risk}] {finding.type}")
    if finding.url:
        st.caption(f"URL：{finding.url}")
    if finding.source:
        st.caption(f"来源：{finding.source}")
    if finding.path:
        st.caption(f"路径：{finding.path}")
    st.caption(f"说明：{finding.message}")
    st.caption(f"建议：{finding.suggestion}")


def _render_limited_text_list(
    label: str,
    items: list[str],
    *,
    total_count: int | None = None,
    truncated: bool = False,
) -> None:
    """按样本形式渲染长列表。"""
    if not items:
        return

    total = total_count if total_count is not None else len(items)
    st.caption(f"{label}（显示 {len(items)} / {total}）")
    st.code("\n".join(items))
    if truncated and total > len(items):
        st.info(f"{label} 过长，已只展示前 {len(items)} 条。")


def _split_resolved_ips(resolved_ips: list[str]) -> tuple[str, str]:
    """提取摘要用的 IPv4 和 IPv6 地址。"""
    ipv4 = ""
    ipv6 = ""
    for ip in resolved_ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.version == 4 and not ipv4:
            ipv4 = ip
        elif parsed.version == 6 and not ipv6:
            ipv6 = ip
        if ipv4 and ipv6:
            break
    return ipv4, ipv6


def _group_resolved_ips(resolved_ips: list[str]) -> tuple[list[str], list[str]]:
    """按地址族整理解析结果。"""
    ipv4_list: list[str] = []
    ipv6_list: list[str] = []
    for ip in resolved_ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.version == 4:
            ipv4_list.append(ip)
        else:
            ipv6_list.append(ip)
    return ipv4_list, ipv6_list


def _render_page_scan(page_scan: SectionView[PageScanViewData] | None) -> None:
    """展示页面级安全检查结果。"""
    st.subheader("页面级安全检查")
    if not page_scan or page_scan.enabled is not True:
        st.info("页面级安全检查未启用。")
        return

    st.write(
        f"已扫描 {page_scan.data.pages_scanned} / {page_scan.data.max_pages} 页，"
        f"最大深度 {page_scan.data.max_depth}，"
        f"发现问题 {page_scan.data.finding_count} 个，"
        f"高 {page_scan.data.risk_counts.get('高', 0)} / "
        f"中 {page_scan.data.risk_counts.get('中', 0)} / "
        f"低 {page_scan.data.risk_counts.get('低', 0)}，"
        f"最高风险 {page_scan.data.highest_risk}"
    )
    message = page_scan.data.message
    if message:
        st.warning(message)
    for warning in page_scan.warnings:
        st.info(warning)

    findings = page_scan.findings
    if findings:
        grouped = _group_findings_by_risk(findings)
        st.caption(f"高 {len(grouped['高'])} 个，中 {len(grouped['中'])} 个，低 {len(grouped['低'])} 个")
        if grouped["高"]:
            st.subheader("高风险结果")
            for idx, finding in enumerate(grouped["高"], start=1):
                _render_page_finding_item(idx, finding)
        if grouped["中"]:
            with st.expander("显示等级为中的结果"):
                for idx, finding in enumerate(grouped["中"], start=1):
                    _render_page_finding_item(idx, finding)
        if grouped["低"]:
            with st.expander("显示等级为低的结果"):
                for idx, finding in enumerate(grouped["低"], start=1):
                    _render_page_finding_item(idx, finding)
    else:
        st.success("未发现页面级安全问题。")

    redirect_issues = page_scan.data.redirect_issues
    if redirect_issues:
        st.caption("重定向链记录")
        st.code(
            "\n".join(
                f"{item.status_code} {item.source} -> {item.target}"
                for item in redirect_issues
            )
        )


def _render_messages(errors: list[str], warnings: list[str]) -> None:
    """展示聚合后的检测错误和警告。"""
    if not errors and not warnings:
        return

    st.divider()
    st.subheader("检测过程提示")
    if errors:
        st.warning("部分检测项执行异常，结果可能不完整：")
        for error in errors:
            st.write(f"- {error}")
    if warnings:
        st.info("检测过程中产生以下提示：")
        for warning in warnings:
            st.write(f"- {warning}")


def _render_page_finding_item(idx: int, finding: FindingView) -> None:
    """渲染页面级单条发现。"""
    st.write(f"{idx}. [{finding.risk}] {finding.type}")
    st.caption(f"页面：{finding.url}")
    st.caption(f"说明：{finding.message}")
    st.caption(f"建议：{finding.suggestion}")

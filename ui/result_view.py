import ipaddress
from typing import Any

import streamlit as st


def render_scan_result(result: dict[str, Any]) -> None:
    """渲染扫描结果。"""
    st.subheader("检测结果概览")

    col1, col2, col3 = st.columns(3)
    col1.metric("安全评分", f"{result['score']}/100")
    col2.metric("安全等级", result["level"])
    col3.metric("HTTPS", "是" if result["https"] is True else "否")

    page_summary = result.get("page_scan_summary", {})
    if page_summary.get("enabled"):
        risk_counts = page_summary.get("risk_counts", {})
        st.caption(
            f"页面扫描：已检查 {page_summary.get('pages_scanned', 0)} 页，"
            f"发现 {page_summary.get('finding_count', 0)} 个问题，"
            f"高 {risk_counts.get('高', 0)} / 中 {risk_counts.get('中', 0)} / 低 {risk_counts.get('低', 0)}，"
            f"最高风险 {page_summary.get('highest_risk', '无')}"
        )

    st.divider()
    st.subheader("基础信息")
    st.write("检测地址：", result["url"])
    st.write("主机名称：", result["host"])
    resolved_ips = result.get("resolved_ips", [])
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

    st.divider()
    st.subheader("TLS/SSL 检测")
    if result["ssl_valid"] is None:
        st.info("SSL 检测已关闭。")
    else:
        st.write("SSL 证书有效：", "是" if result["ssl_valid"] else "否")

    if result["ssl_valid"]:
        st.write("证书剩余天数：", result["ssl_days_left"])
    elif result["ssl_valid"] is False:
        st.warning("未检测到有效的 SSL 证书，或证书检测失败。")

    st.divider()
    st.subheader("HTTP 安全头检测")
    if result["security_header_score"] is None:
        st.info("安全响应头检测已关闭。")
    else:
        st.write("安全头得分：", result["security_header_score"])

    if result["missing_security_headers"]:
        st.warning("存在缺失的安全响应头：")
        st.code("\n".join(result["missing_security_headers"]))
    elif result["missing_security_headers"] == []:
        st.success("未发现缺失的安全响应头。")

    st.divider()
    _render_http_methods(result)

    st.divider()
    st.subheader("敏感路径检测")
    if result["sensitive_paths"]:
        st.warning("发现可能存在的敏感路径：")
        st.code("\n".join(result["sensitive_paths"]))
    elif result["sensitive_paths"] == []:
        st.success("未发现常见敏感路径。")
    else:
        st.info("敏感路径检测已关闭。")

    st.divider()
    st.subheader("暴露信息检测")
    info_leak = result.get("info_leak", {})
    _render_exposure_status(
        info_leak.get("version_exposed"),
        "响应头中存在可识别的服务器版本特征。",
        "未发现明显的服务器版本特征。",
        "服务器版本特征未检测。",
    )
    _render_exposure_status(
        info_leak.get("framework_exposed"),
        "响应头中存在可识别的框架特征。",
        "未发现明显的框架特征。",
        "框架特征未检测。",
    )
    _render_exposure_status(
        info_leak.get("meta_exposed"),
        "页面源码中存在可识别的重点 meta 字段。",
        "未发现明显的重点 meta 字段。",
        "重点 meta 字段未检测。",
    )
    _render_info_leak_details(info_leak)

    _render_page_scan(result.get("page_scan"))
    st.divider()
    _render_sitecheck(result.get("page_scan", {}).get("sitecheck") if result.get("page_scan") else None)
    _render_errors(result.get("errors", []))

    st.divider()
    with st.expander("查看原始检测结果"):
        st.json(result)


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


def _render_http_methods(result: dict[str, Any]) -> None:
    """展示 HTTP 方法检测结果。"""
    st.subheader("HTTP 方法检测")
    method_info = result.get("http_methods", {})
    if method_info.get("enabled") is None:
        st.info("HTTP 方法检测已关闭。")
        return

    st.write(f"OPTIONS 响应状态：{_format_http_status(method_info.get('options_status'))}")
    if method_info.get("allow_methods"):
        st.caption(f"Allow：{', '.join(method_info['allow_methods'])}")
    if method_info.get("cors_methods"):
        st.caption(f"Access-Control-Allow-Methods：{', '.join(method_info['cors_methods'])}")

    for warning in method_info.get("warnings", []):
        st.info(warning)

    exposed_methods = method_info.get("exposed_methods", [])
    if method_info.get("trace_enabled") is True:
        st.error("TRACE 方法已启用，存在一定安全风险。")
        if exposed_methods:
            st.warning(f"同时发现可能暴露的其他 HTTP 方法：{', '.join(exposed_methods)}")
    elif exposed_methods:
        st.warning(f"发现可能暴露的 HTTP 方法：{', '.join(exposed_methods)}")
    elif method_info.get("trace_enabled") is False:
        st.success("未发现明显的 HTTP 方法暴露。")
    else:
        st.info("HTTP 方法检测结果不完整。")


def _render_info_leak_details(info_leak: dict[str, Any]) -> None:
    """展示响应头和 meta 的细节暴露项。"""
    header_findings = info_leak.get("header_findings", [])
    meta_fields = info_leak.get("meta_fields", [])
    if not header_findings and not meta_fields:
        return

    with st.expander("查看暴露详情"):
        if header_findings:
            st.caption("响应头暴露")
            for finding in header_findings:
                st.write(f"- {finding.get('field', '响应头')}: {finding.get('value', '')}")
                st.caption(f"说明：{finding.get('message', '')}")
                st.caption(f"建议：{finding.get('suggestion', '')}")

        if meta_fields:
            st.caption("页面源码 meta")
            for finding in meta_fields:
                st.write(f"- {finding.get('field', 'meta')}: {finding.get('value', '')}")
                st.caption(f"说明：{finding.get('message', '')}")
                st.caption(f"建议：{finding.get('suggestion', '')}")


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


def _render_sitecheck(sitecheck: dict[str, Any] | None) -> None:
    """展示 robots.txt / sitemap.xml 暴露面分析。"""
    st.subheader("robots.txt / sitemap.xml 暴露面分析")
    if not sitecheck or not sitecheck.get("enabled"):
        st.info("robots.txt / sitemap.xml 暴露面分析未启用。")
        return

    crawl_policy = sitecheck.get("crawl_policy", {})
    sitemap = sitecheck.get("sitemap", {})
    risk_counts = sitecheck.get("risk_counts", {})
    st.write(
        f"状态：{sitecheck.get('status', '未知')}，"
        f"robots 声明 {sitecheck.get('sitemap_url_count', 0)} 个 sitemap，"
        f"发现项 {sitecheck.get('finding_count', 0)} 个，"
        f"高 {risk_counts.get('高', 0)} / 中 {risk_counts.get('中', 0)} / 低 {risk_counts.get('低', 0)}，"
        f"可继续分析入口 {sitecheck.get('seed_url_count', 0)} 个，"
        f"最高风险 {sitecheck.get('highest_risk', '无')}"
    )
    st.caption(f"robots.txt：{sitecheck.get('robots_url', crawl_policy.get('robots_url', ''))}")

    with st.expander("查看 robots.txt 详情"):
        st.write(f"robots.txt 状态：{crawl_policy.get('status', '未知')}")
        _render_limited_text_list("Allow 规则", crawl_policy.get("allow_paths", []))
        _render_limited_text_list("Disallow 规则", crawl_policy.get("disallow_paths", []))
        _render_limited_text_list("Sitemap 声明", crawl_policy.get("sitemap_urls", []))
        _render_ranked_findings("robots.txt 问题", crawl_policy.get("findings", []))
        for warning in crawl_policy.get("warnings", []):
            st.info(warning)

    with st.expander("查看 sitemap.xml 详情"):
        st.write(f"sitemap 状态：{sitemap.get('status', '未知')}")
        st.write(
            f"子 sitemap {sitemap.get('sitemap_count', 0)} 个，"
            f"页面入口 {sitemap.get('url_count', 0)} 个"
        )
        _render_limited_text_list(
            "候选 sitemap",
            sitemap.get("candidate_urls", []),
            total_count=sitemap.get("candidate_url_count"),
            truncated=bool(sitemap.get("candidate_urls_truncated")),
        )
        _render_limited_text_list(
            "可继续分析的页面入口",
            sitemap.get("seed_urls", []),
            total_count=sitemap.get("seed_url_count"),
            truncated=bool(sitemap.get("seed_urls_truncated")),
        )
        _render_ranked_findings(
            "sitemap.xml 问题",
            sitemap.get("findings", []),
            total_count=sitemap.get("finding_count"),
            truncated=bool(sitemap.get("findings_truncated")),
        )
        for warning in sitemap.get("warnings", []):
            st.info(warning)


def _render_ranked_findings(
    section_label: str,
    findings: list[dict[str, Any]],
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


def _group_findings_by_risk(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """按风险等级分组发现。"""
    grouped: dict[str, list[dict[str, Any]]] = {"高": [], "中": [], "低": []}
    for finding in findings:
        risk = finding.get("risk", "")
        if risk not in grouped:
            continue
        grouped[risk].append(finding)
    return grouped


def _render_finding_item(idx: int, finding: dict[str, Any]) -> None:
    """渲染单条发现。"""
    st.write(f"{idx}. [{finding.get('risk', '低')}] {finding.get('type', '发现项')}")
    if finding.get("url"):
        st.caption(f"URL：{finding['url']}")
    if finding.get("source"):
        st.caption(f"来源：{finding['source']}")
    if finding.get("path"):
        st.caption(f"路径：{finding['path']}")
    st.caption(f"说明：{finding.get('message', '')}")
    st.caption(f"建议：{finding.get('suggestion', '')}")


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


def _render_page_scan(page_scan: dict[str, Any] | None) -> None:
    """展示页面级安全检查结果。"""
    st.subheader("页面级安全检查")
    if not page_scan or not page_scan.get("enabled"):
        st.info("页面级安全检查未启用。")
        return

    st.write(
        f"已扫描 {page_scan.get('pages_scanned', 0)} / {page_scan.get('max_pages', 0)} 页，"
        f"最大深度 {page_scan.get('max_depth', 0)}，"
        f"发现问题 {page_scan.get('finding_count', 0)} 个，"
        f"高 {page_scan.get('risk_counts', {}).get('高', 0)} / "
        f"中 {page_scan.get('risk_counts', {}).get('中', 0)} / "
        f"低 {page_scan.get('risk_counts', {}).get('低', 0)}，"
        f"最高风险 {page_scan.get('highest_risk', '无')}"
    )
    if page_scan.get("message"):
        st.warning(page_scan["message"])
    for warning in page_scan.get("warnings", []):
        st.info(warning)

    findings = page_scan.get("findings", [])
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

    redirect_issues = page_scan.get("redirect_issues", [])
    if redirect_issues:
        st.caption("重定向链记录")
        st.code(
            "\n".join(
                f"{item['status_code']} {item['from']} -> {item['to']}"
                for item in redirect_issues
            )
        )


def _render_errors(errors: list[str]) -> None:
    """展示检测过程中的异常提示。"""
    if not errors:
        return

    st.divider()
    st.subheader("检测过程提示")
    st.warning("部分检测项执行异常，结果可能不完整：")
    for error in errors:
        st.write(f"- {error}")


def _render_page_finding_item(idx: int, finding: dict[str, Any]) -> None:
    """渲染页面级单条发现。"""
    st.write(f"{idx}. [{finding.get('risk', '低')}] {finding.get('type', '发现项')}")
    st.caption(f"页面：{finding.get('url', '')}")
    st.caption(f"说明：{finding.get('message', '')}")
    st.caption(f"建议：{finding.get('suggestion', '')}")

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
        st.caption(
            f"页面扫描：已检查 {page_summary.get('pages_scanned', 0)} 页，"
            f"发现 {page_summary.get('finding_count', 0)} 个问题，"
                f"最高风险 {page_summary.get('highest_risk', '无')}"
        )

    st.divider()
    st.subheader("基础信息")
    st.write("检测地址：", result["url"])
    st.write("主机名称：", result["host"])

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
    st.subheader("TRACE 方法检测")
    if result["trace_enabled"] is True:
        st.error("TRACE 方法已启用，存在一定安全风险。")
    elif result["trace_enabled"] is False:
        st.success("TRACE 方法未启用。")
    else:
        st.info("TRACE 方法检测已关闭。")

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
    st.subheader("信息泄露检测")
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

    st.divider()
    _render_page_scan(result.get("page_scan"))
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
        f"最高风险 {page_scan.get('highest_risk', '无')}"
    )
    if page_scan.get("message"):
        st.warning(page_scan["message"])
    for warning in page_scan.get("warnings", []):
        st.info(warning)

    findings = page_scan.get("findings", [])
    if findings:
        for idx, finding in enumerate(findings, start=1):
            st.write(f"{idx}. [{finding['risk']}] {finding['type']}")
            st.caption(f"页面：{finding['url']}")
            st.caption(f"说明：{finding['message']}")
            st.caption(f"建议：{finding['suggestion']}")
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

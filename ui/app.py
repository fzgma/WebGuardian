# ui/app.py
import time

import streamlit as st

from scanner.scanner import scan
from scanner.options import ScanOptions


def _preset_options(profile: str) -> ScanOptions:
    """返回预设扫描配置。"""
    if profile == "快速模式":
        return ScanOptions(
            check_https=True,
            check_ssl=True,
            check_security_headers=True,
            check_trace=False,
            check_sensitive_paths=False,
            check_info_leak=True,
            check_page_scan=False,
        )

    if profile == "深度模式":
        return ScanOptions(
            check_https=True,
            check_ssl=True,
            check_security_headers=True,
            check_trace=True,
            check_sensitive_paths=True,
            check_info_leak=True,
            check_page_scan=True,
            check_page_mixed_content=True,
            check_page_forms=True,
            check_page_cookie_flags=True,
            check_page_redirects=True,
            check_page_headers=True,
            check_page_exposed_info=True,
            page_scan_max_pages=10,
            page_scan_max_depth=2,
        )

    return ScanOptions(
        check_https=True,
        check_ssl=True,
        check_security_headers=True,
        check_trace=True,
        check_sensitive_paths=True,
        check_info_leak=True,
        check_page_scan=False,
    )


def _apply_profile(profile: str) -> None:
    """把预设模式写回会话状态。"""
    defaults = _preset_options(profile)
    st.session_state["check_https"] = defaults.check_https
    st.session_state["check_ssl"] = defaults.check_ssl
    st.session_state["check_security_headers"] = defaults.check_security_headers
    st.session_state["check_trace"] = defaults.check_trace
    st.session_state["check_sensitive_paths"] = defaults.check_sensitive_paths
    st.session_state["check_info_leak"] = defaults.check_info_leak
    st.session_state["check_page_scan"] = defaults.check_page_scan
    st.session_state["check_page_mixed_content"] = defaults.check_page_mixed_content
    st.session_state["check_page_forms"] = defaults.check_page_forms
    st.session_state["check_page_cookie_flags"] = defaults.check_page_cookie_flags
    st.session_state["check_page_redirects"] = defaults.check_page_redirects
    st.session_state["check_page_headers"] = defaults.check_page_headers
    st.session_state["check_page_exposed_info"] = defaults.check_page_exposed_info
    st.session_state["page_scan_max_pages"] = defaults.page_scan_max_pages
    st.session_state["page_scan_max_depth"] = defaults.page_scan_max_depth


def _sync_page_scan_defaults() -> None:
    """初始化页面级扫描默认值。"""
    defaults = _preset_options("深度模式")
    if "check_page_scan" not in st.session_state:
        st.session_state["check_page_scan"] = defaults.check_page_scan
    if "check_page_mixed_content" not in st.session_state:
        st.session_state["check_page_mixed_content"] = defaults.check_page_mixed_content
    if "check_page_forms" not in st.session_state:
        st.session_state["check_page_forms"] = defaults.check_page_forms
    if "check_page_cookie_flags" not in st.session_state:
        st.session_state["check_page_cookie_flags"] = defaults.check_page_cookie_flags
    if "check_page_redirects" not in st.session_state:
        st.session_state["check_page_redirects"] = defaults.check_page_redirects
    if "check_page_headers" not in st.session_state:
        st.session_state["check_page_headers"] = defaults.check_page_headers
    if "check_page_exposed_info" not in st.session_state:
        st.session_state["check_page_exposed_info"] = defaults.check_page_exposed_info
    if "page_scan_max_pages" not in st.session_state:
        st.session_state["page_scan_max_pages"] = defaults.page_scan_max_pages
    if "page_scan_max_depth" not in st.session_state:
        st.session_state["page_scan_max_depth"] = defaults.page_scan_max_depth


def _mark_custom() -> None:
    """将当前模式标记为自定义。"""
    st.session_state["scan_profile"] = "自定义模式"


def run_app():
    """启动 Streamlit 页面。"""

    st.set_page_config(
        page_title="WebGuardian 网站安全检测工具",
        layout="centered"
    )

    st.title("WebGuardian 网站安全检测工具")
    st.caption("输入网站地址后，系统将进行基础安全检测并生成评分结果。")

    st.subheader("扫描配置")
    if "scan_profile" not in st.session_state:
        st.session_state["scan_profile"] = "标准模式"
    _sync_page_scan_defaults()

    current_profile = st.session_state["scan_profile"]
    if current_profile != "自定义模式":
        _apply_profile(current_profile)

    profile = st.radio(
        "预设模式",
        ["标准模式", "快速模式", "深度模式", "自定义模式"],
        horizontal=True,
        key="scan_profile",
    )

    defaults = _preset_options(profile if profile != "自定义模式" else "标准模式")

    col_a, col_b = st.columns(2)
    with col_a:
        check_https = st.checkbox(
            "HTTPS 检测",
            value=defaults.check_https,
            key="check_https",
            on_change=_mark_custom,
        )
        check_ssl = st.checkbox(
            "SSL 证书检测",
            value=defaults.check_ssl,
            key="check_ssl",
            on_change=_mark_custom,
        )
        check_security_headers = st.checkbox(
            "安全响应头检测",
            value=defaults.check_security_headers,
            key="check_security_headers",
            on_change=_mark_custom,
        )
        check_trace = st.checkbox(
            "TRACE 方法检测",
            value=defaults.check_trace,
            key="check_trace",
            on_change=_mark_custom,
        )

    with col_b:
        check_sensitive_paths = st.checkbox(
            "敏感路径检测",
            value=defaults.check_sensitive_paths,
            key="check_sensitive_paths",
            on_change=_mark_custom,
        )
        check_info_leak = st.checkbox(
            "信息泄露检测",
            value=defaults.check_info_leak,
            key="check_info_leak",
            on_change=_mark_custom,
        )

    st.divider()
    st.subheader("页面级安全检查")
    st.caption("仅对同源 HTML 页面做轻量抓取分析，检查常见的安全问题。")

    page_scan_enabled = st.checkbox(
        "启用页面级安全检查",
        value=st.session_state["check_page_scan"],
        key="check_page_scan",
        on_change=_mark_custom,
        help="从首页开始，同源、限深、限页分析页面自身的安全暴露面。",
    )

    if page_scan_enabled:
        page_col_a, page_col_b = st.columns(2)
        with page_col_a:
            st.number_input(
                "最大页面数",
                min_value=1,
                max_value=50,
                step=1,
                key="page_scan_max_pages",
                on_change=_mark_custom,
                help="最多只抓取这么多页，避免扫描范围失控。",
            )
        with page_col_b:
            st.number_input(
                "最大深度",
                min_value=0,
                max_value=5,
                step=1,
                key="page_scan_max_depth",
                on_change=_mark_custom,
                help="从首页开始向下抓取的层数限制。",
            )

        page_sub_a, page_sub_b = st.columns(2)
        with page_sub_a:
            st.checkbox(
                "混合内容",
                value=st.session_state["check_page_mixed_content"],
                key="check_page_mixed_content",
                on_change=_mark_custom,
                help="检查 HTTPS 页面是否加载 http:// 资源。",
            )
            st.checkbox(
                "不安全表单",
                value=st.session_state["check_page_forms"],
                key="check_page_forms",
                on_change=_mark_custom,
                help="检查 form action 是否指向 http://。",
            )
            st.checkbox(
                "Cookie 安全属性",
                value=st.session_state["check_page_cookie_flags"],
                key="check_page_cookie_flags",
                on_change=_mark_custom,
                help="检查 Secure、HttpOnly、SameSite。",
            )
        with page_sub_b:
            st.checkbox(
                "重定向链",
                value=st.session_state["check_page_redirects"],
                key="check_page_redirects",
                on_change=_mark_custom,
                help="检查是否发生 HTTPS 到 HTTP 或跨源跳转。",
            )
            st.checkbox(
                "页面响应头",
                value=st.session_state["check_page_headers"],
                key="check_page_headers",
                on_change=_mark_custom,
                help="检查重点页面是否缺少 CSP、HSTS 等头。",
            )
            st.checkbox(
                "暴露性信息",
                value=st.session_state["check_page_exposed_info"],
                key="check_page_exposed_info",
                on_change=_mark_custom,
                help="检查页面源码是否直接暴露内网地址、测试路径或调试信息。",
            )

        page_hint = [
            "扫描页数受限",
            "仅跟进同源链接",
            "只解析 HTML 页面",
        ]
        st.caption("，".join(page_hint))

    if profile == "自定义模式":
        st.caption("当前为自定义模式，修改下方选项后会自动保持自定义。")
    elif profile != current_profile:
        st.caption(f"已切换到 {profile}，下方选项已同步。")

    with st.form("scan_form", clear_on_submit=False):
        url = st.text_input(
            "请输入网站地址",
            placeholder="例如：https://example.com",
        )
        submitted = st.form_submit_button("开始检测", type="primary")

    if submitted:
        if not url.strip():
            st.warning("请先输入网站地址。")
            return

        progress_bar = st.progress(0)
        progress_text = st.empty()
        progress_text.caption("准备开始检测")
        last_progress = {"percent": -1, "text": ""}
        last_update_at = {"ts": 0.0}

        def on_progress(percent: int, text: str):
            now = time.monotonic()
            percent_changed = percent != last_progress["percent"]
            text_changed = text != last_progress["text"]
            elapsed = now - last_update_at["ts"]
            should_update = (
                percent == 100
                or (percent_changed and elapsed >= 0.5)
                or (text_changed and elapsed >= 0.5)
            )
            if not should_update:
                return
            last_progress["percent"] = percent
            last_progress["text"] = text
            last_update_at["ts"] = now
            progress_bar.progress(percent)
            progress_text.caption(text)

        options = ScanOptions(
            check_https=check_https,
            check_ssl=check_ssl,
            check_security_headers=check_security_headers,
            check_trace=check_trace,
            check_sensitive_paths=check_sensitive_paths,
            check_info_leak=check_info_leak,
            check_page_scan=st.session_state["check_page_scan"],
            check_page_mixed_content=st.session_state["check_page_mixed_content"],
            check_page_forms=st.session_state["check_page_forms"],
            check_page_cookie_flags=st.session_state["check_page_cookie_flags"],
            check_page_redirects=st.session_state["check_page_redirects"],
            check_page_headers=st.session_state["check_page_headers"],
            check_page_exposed_info=st.session_state["check_page_exposed_info"],
            page_scan_max_pages=int(st.session_state["page_scan_max_pages"]),
            page_scan_max_depth=int(st.session_state["page_scan_max_depth"]),
        )

        if options.enabled_items() == 0:
            st.warning("请至少启用一项检测后再开始扫描。")
            return

        if options.check_page_scan and not any(
            (
                options.check_page_mixed_content,
                options.check_page_forms,
                options.check_page_cookie_flags,
                options.check_page_redirects,
                options.check_page_headers,
                options.check_page_exposed_info,
            )
        ):
            st.warning("页面级检查已启用，但未选择任何具体检查项。")
            return

        with st.spinner("正在检测，请稍候..."):
            result = scan(url, progress_callback=on_progress, options=options)


        if not result.get("ok"):
            st.error(f"检测失败：{result.get('error', '未知错误')}")
            return

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
                f"最高风险 {page_summary.get('highest_risk', '低')}"
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

        version_exposed = info_leak.get("version_exposed")
        framework_exposed = info_leak.get("framework_exposed")

        if version_exposed is True:
            st.warning("响应头中存在可识别的服务器版本特征。")
        elif version_exposed is False:
            st.success("未发现明显的服务器版本特征。")
        else:
            st.info("服务器版本特征未检测。")

        if framework_exposed is True:
            st.warning("响应头中存在可识别的框架特征。")
        elif framework_exposed is False:
            st.success("未发现明显的框架特征。")
        else:
            st.info("框架特征未检测。")

        st.divider()

        st.subheader("页面级安全检查")
        page_scan = result.get("page_scan")
        if not page_scan or not page_scan.get("enabled"):
            st.info("页面级安全检查未启用。")
        else:
            st.write(
                f"已扫描 {page_scan.get('pages_scanned', 0)} / {page_scan.get('max_pages', 0)} 页，"
                f"最大深度 {page_scan.get('max_depth', 0)}，"
                f"发现问题 {page_scan.get('finding_count', 0)} 个，"
                f"最高风险 {page_scan.get('highest_risk', '低')}"
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

        if result.get("errors"):
            st.divider()
            st.subheader("检测过程提示")
            st.warning("部分检测项执行异常，结果可能不完整：")
            for error in result["errors"]:
                st.write(f"- {error}")

        st.divider()

        with st.expander("查看原始检测结果"):
            st.json(result)


if __name__ == "__main__":
    run_app()

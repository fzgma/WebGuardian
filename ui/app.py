# ui/app.py
import streamlit as st

from scanner.scanner import scan
from scanner.options import ScanOptions


def _preset_options(profile: str) -> ScanOptions:
    if profile == "快速模式":
        return ScanOptions(
            check_https=True,
            check_ssl=True,
            check_security_headers=True,
            check_trace=False,
            check_sensitive_paths=False,
            check_ports=False,
            check_info_leak=True,
        )

    if profile == "深度模式":
        return ScanOptions()

    return ScanOptions(
        check_https=True,
        check_ssl=True,
        check_security_headers=True,
        check_trace=True,
        check_sensitive_paths=True,
        check_ports=False,
        check_info_leak=True,
    )


def _apply_profile(profile: str) -> None:
    defaults = _preset_options(profile)
    st.session_state["check_https"] = defaults.check_https
    st.session_state["check_ssl"] = defaults.check_ssl
    st.session_state["check_security_headers"] = defaults.check_security_headers
    st.session_state["check_trace"] = defaults.check_trace
    st.session_state["check_sensitive_paths"] = defaults.check_sensitive_paths
    st.session_state["check_ports"] = defaults.check_ports
    st.session_state["check_info_leak"] = defaults.check_info_leak


def _mark_custom() -> None:
    st.session_state["scan_profile"] = "自定义模式"


def run_app():
    """
    Streamlit 页面入口函数。
    负责用户输入、调用扫描逻辑、展示检测结果。
    """

    # 页面基础配置
    st.set_page_config(
        page_title="WebGuardian 网站安全检测工具",
        layout="centered"
    )

    st.title("WebGuardian 网站安全检测工具")
    st.caption("输入网站地址后，系统将进行基础安全检测并生成评分结果。")

    st.subheader("扫描配置")
    if "scan_profile" not in st.session_state:
        st.session_state["scan_profile"] = "标准模式"

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
        check_ports = st.checkbox(
            "端口检测",
            value=defaults.check_ports,
            key="check_ports",
            on_change=_mark_custom,
        )
        check_info_leak = st.checkbox(
            "信息泄露检测",
            value=defaults.check_info_leak,
            key="check_info_leak",
            on_change=_mark_custom,
        )

    if profile == "自定义模式":
        st.caption("当前为自定义模式，修改下方选项后会自动保持自定义。")
    elif profile != current_profile:
        st.caption(f"已切换到 {profile}，下方选项已同步。")

    # 用户输入区域
    url = st.text_input(
        "请输入网站地址",
        placeholder="例如：https://example.com"
    )

    # 点击按钮后开始检测
    if st.button("开始检测", type="primary"):
        if not url.strip():
            st.warning("请先输入网站地址。")
            return

        progress_bar = st.progress(0, text="准备开始检测")

        def on_progress(percent: int, text: str):
            progress_bar.progress(percent, text=text)

        options = ScanOptions(
            check_https=check_https,
            check_ssl=check_ssl,
            check_security_headers=check_security_headers,
            check_trace=check_trace,
            check_sensitive_paths=check_sensitive_paths,
            check_ports=check_ports,
            check_info_leak=check_info_leak,
        )

        if options.enabled_items() == 0:
            st.warning("请至少启用一项检测后再开始扫描。")
            return

        # 调用 scanner 层进行检测
        with st.spinner("正在检测，请稍候..."):
            result = scan(url, progress_callback=on_progress, options=options)


        # 如果检测入口校验失败，则直接展示错误信息
        if not result.get("ok"):
            st.error(f"检测失败：{result.get('error', '未知错误')}")
            return

        # 展示核心评分信息
        st.subheader("检测结果概览")

        col1, col2, col3 = st.columns(3)
        col1.metric("安全评分", f"{result['score']}/100")
        col2.metric("安全等级", result["level"])
        col3.metric("HTTPS", "是" if result["https"] else "否")

        st.divider()

        # 展示基础信息
        st.subheader("基础信息")
        st.write("检测地址：", result["url"])
        st.write("主机名称：", result["host"])

        st.divider()

        # TLS/SSL 检测结果
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

        # HTTP 安全响应头检测结果
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

        # TRACE 方法检测
        st.subheader("TRACE 方法检测")

        if result["trace_enabled"] is True:
            st.error("TRACE 方法已启用，存在一定安全风险。")
        elif result["trace_enabled"] is False:
            st.success("TRACE 方法未启用。")
        else:
            st.info("TRACE 方法检测已关闭。")

        st.divider()

        # 敏感路径检测
        st.subheader("敏感路径检测")

        if result["sensitive_paths"]:
            st.warning("发现可能存在的敏感路径：")
            st.code("\n".join(result["sensitive_paths"]))
        elif result["sensitive_paths"] == []:
            st.success("未发现常见敏感路径。")
        else:
            st.info("敏感路径检测已关闭。")

        st.divider()

        # 端口检测
        st.subheader("端口检测")

        if result["open_ports"]:
            st.write("开放端口：", result["open_ports"])
        elif result["open_ports"] == []:
            st.write("未发现开放的常见端口。")
        else:
            st.info("端口检测已关闭。")

        st.divider()

        # 信息泄露检测
        st.subheader("信息泄露检测")

        info_leak = result.get("info_leak", {})

        server_header_exists = info_leak.get("server_header_exists")
        x_powered_by_exists = info_leak.get("x_powered_by_exists")

        if server_header_exists is True:
            st.warning("响应头中存在 Server 字段，可能泄露服务器信息。")
        elif server_header_exists is False:
            st.success("响应头中未发现 Server 字段。")
        else:
            st.info("Server 字段未检测。")

        if x_powered_by_exists is True:
            st.warning("响应头中存在 X-Powered-By 字段，可能泄露技术栈信息。")
        elif x_powered_by_exists is False:
            st.success("响应头中未发现 X-Powered-By 字段。")
        else:
            st.info("X-Powered-By 字段未检测。")

        # 展示部分异常，但不中断整体结果
        if result.get("errors"):
            st.divider()
            st.subheader("检测过程提示")
            st.warning("部分检测项执行异常，结果可能不完整：")
            for error in result["errors"]:
                st.write(f"- {error}")

        st.divider()

        # 原始数据展示，便于调试和后续扩展
        with st.expander("查看原始检测结果"):
            st.json(result)


if __name__ == "__main__":
    run_app()

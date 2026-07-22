"""扫描配置组件。"""

import streamlit as st

from scanner.options import ScanOptions

_PROFILE_OPTIONS = ["标准模式", "快速模式", "深度模式", "自定义模式"]
_BASIC_OPTION_KEYS = (
    "check_https",
    "check_ssl",
    "check_security_headers",
    "check_trace",
    "check_sensitive_paths",
    "check_info_leak",
)
_PAGE_OPTION_KEYS = (
    "check_page_scan",
    "check_page_mixed_content",
    "check_page_forms",
    "check_page_cookie_flags",
    "check_page_redirects",
    "check_page_headers",
    "check_page_exposed_info",
    "page_scan_max_pages",
    "page_scan_max_depth",
)
_SCAN_OPTION_KEYS = _BASIC_OPTION_KEYS + _PAGE_OPTION_KEYS


@st.fragment
def render_scan_config() -> ScanOptions:
    """渲染扫描配置并返回当前选项。"""
    st.subheader("扫描配置")
    _initialize_state()

    st.radio(
        "预设模式",
        _PROFILE_OPTIONS,
        horizontal=True,
        key="scan_profile",
        on_change=_on_profile_change,
    )

    profile = st.session_state["scan_profile"]
    if profile != "自定义模式":
        _apply_profile(profile)

    defaults = _preset_options(profile if profile != "自定义模式" else "标准模式")

    (
        check_https,
        check_ssl,
        check_security_headers,
        check_trace,
        check_sensitive_paths,
        check_info_leak,
    ) = _render_basic_options(defaults)
    _render_page_scan_options(defaults)

    if profile == "自定义模式":
        st.caption("当前为自定义模式，可以手动调整下方选项。")

    return ScanOptions.from_dict({key: st.session_state[key] for key in _SCAN_OPTION_KEYS})


def validate_scan_options(options: ScanOptions) -> str | None:
    """返回扫描配置的校验错误。"""
    if options.enabled_items() == 0:
        return "请至少启用一项检测后再开始扫描。"

    page_checks = (
        options.check_page_mixed_content,
        options.check_page_forms,
        options.check_page_cookie_flags,
        options.check_page_redirects,
        options.check_page_headers,
        options.check_page_exposed_info,
    )
    if options.check_page_scan and not any(page_checks):
        return "页面级检查已启用，但未选择任何具体检查项。"
    return None


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


def _initialize_state() -> None:
    """初始化配置会话状态。"""
    if "scan_profile" not in st.session_state:
        st.session_state["scan_profile"] = "标准模式"

    defaults = _preset_options("标准模式")
    for key, value in (
        ("check_https", defaults.check_https),
        ("check_ssl", defaults.check_ssl),
        ("check_security_headers", defaults.check_security_headers),
        ("check_trace", defaults.check_trace),
        ("check_sensitive_paths", defaults.check_sensitive_paths),
        ("check_info_leak", defaults.check_info_leak),
    ):
        st.session_state.setdefault(key, value)

    for key, value in (
        ("check_page_scan", defaults.check_page_scan),
        ("check_page_mixed_content", defaults.check_page_mixed_content),
        ("check_page_forms", defaults.check_page_forms),
        ("check_page_cookie_flags", defaults.check_page_cookie_flags),
        ("check_page_redirects", defaults.check_page_redirects),
        ("check_page_headers", defaults.check_page_headers),
        ("check_page_exposed_info", defaults.check_page_exposed_info),
        ("page_scan_max_pages", defaults.page_scan_max_pages),
        ("page_scan_max_depth", defaults.page_scan_max_depth),
    ):
        st.session_state.setdefault(key, value)


def _apply_profile(profile: str) -> None:
    """把预设模式写回会话状态。"""
    defaults = _preset_options(profile)
    for key, value in defaults.to_dict().items():
        st.session_state[key] = value


def _on_profile_change() -> None:
    """根据选择的预设模式更新会话状态。"""
    profile = st.session_state["scan_profile"]
    if profile != "自定义模式":
        _apply_profile(profile)


def _mark_custom() -> None:
    """将当前模式标记为自定义。"""
    st.session_state["scan_profile"] = "自定义模式"


def _render_basic_options(
    defaults: ScanOptions,
) -> tuple[bool, bool, bool, bool, bool, bool]:
    """渲染基础检测选项。"""
    col_a, col_b = st.columns(2)
    with col_a:
        check_https = st.checkbox("HTTPS 检测", key="check_https", on_change=_mark_custom)
        check_ssl = st.checkbox("SSL 证书检测", key="check_ssl", on_change=_mark_custom)
        check_security_headers = st.checkbox(
            "安全响应头检测",
            key="check_security_headers",
            on_change=_mark_custom,
        )
        check_trace = st.checkbox("TRACE 方法检测", key="check_trace", on_change=_mark_custom)

    with col_b:
        check_sensitive_paths = st.checkbox(
            "敏感路径检测",
            key="check_sensitive_paths",
            on_change=_mark_custom,
        )
        check_info_leak = st.checkbox(
            "信息泄露检测",
            key="check_info_leak",
            on_change=_mark_custom,
        )
    return (
        check_https,
        check_ssl,
        check_security_headers,
        check_trace,
        check_sensitive_paths,
        check_info_leak,
    )


def _render_page_scan_options(defaults: ScanOptions) -> None:
    """渲染页面级安全检查选项。"""
    st.divider()
    st.subheader("页面级安全检查")
    st.caption("仅对同源 HTML 页面做轻量抓取分析，检查常见的安全问题。")
    page_scan_enabled = st.checkbox(
        "启用页面级安全检查",
        key="check_page_scan",
        on_change=_mark_custom,
        help="从首页开始，同源、限深、限页分析页面自身的安全暴露面。",
    )
    if not page_scan_enabled:
        return

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
        _render_page_checkbox(
            "混合内容", "check_page_mixed_content", "检查 HTTPS 页面是否加载 http:// 资源。"
        )
        _render_page_checkbox(
            "不安全表单", "check_page_forms", "检查 form action 是否指向 http://。"
        )
        _render_page_checkbox(
            "Cookie 安全属性",
            "check_page_cookie_flags",
            "检查 Secure、HttpOnly、SameSite。",
        )
    with page_sub_b:
        _render_page_checkbox(
            "重定向链", "check_page_redirects", "检查是否发生 HTTPS 到 HTTP 或跨源跳转。"
        )
        _render_page_checkbox(
            "页面响应头", "check_page_headers", "检查重点页面是否缺少 CSP、HSTS 等头。"
        )
        _render_page_checkbox(
            "暴露性信息",
            "check_page_exposed_info",
            "检查页面源码是否直接暴露内网地址、测试路径或调试信息。",
        )

    st.caption("，".join(("扫描页数受限", "仅跟进同源链接", "只解析 HTML 页面")))


def _render_page_checkbox(label: str, key: str, help_text: str) -> None:
    """渲染页面级检查开关。"""
    st.checkbox(
        label,
        key=key,
        on_change=_mark_custom,
        help=help_text,
    )

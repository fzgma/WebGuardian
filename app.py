import streamlit as st

from utils.net import validate_input_url
from ui.scan_runtime import get_scan_runtime, render_scan_runtime, start_scan
from ui.scan_config import collect_scan_options, render_scan_config, validate_scan_options


def run_app():
    """启动 Streamlit 页面。"""

    st.set_page_config(
        page_title="WebGuardian 网站安全检测工具",
        layout="centered"
    )

    st.title("WebGuardian 网站安全检测工具")
    st.caption("输入网站地址后开始检测。")

    render_scan_config()
    render_scan_form()

    render_scan_runtime()


@st.fragment(run_every=0.5)
def render_scan_form() -> None:
    """渲染扫描表单并跟随运行态刷新按钮。"""
    runtime = get_scan_runtime()
    running = runtime.is_running()

    with st.form("scan_form", clear_on_submit=False):
        url = st.text_input(
            "请输入网站地址",
            placeholder="例如：example.com , 203.0.113.1:80, [2001:db8::1234]:8080",
            help=(
                "如果输入 IPv6 地址，请确认您的设备和网络环境已启用 IPv6，"
                "否则可能无法连接。"
            ),
        )
        submitted = st.form_submit_button(
            "检测进行中..." if running else "开始检测",
            type="primary",
            disabled=running,
        )

    if not submitted:
        return


    if not url.strip():
        st.warning("请先输入网站地址。")
        return

    url_ok, url_error = validate_input_url(url)
    if not url_ok:
        st.warning(url_error)
        return

    options = collect_scan_options()
    validation_error = validate_scan_options(options)
    if validation_error:
        st.warning(validation_error)
        return

    runtime.clear_previous_result()

    if start_scan(url, options):
        st.rerun(scope="fragment")


if __name__ == "__main__":
    run_app()

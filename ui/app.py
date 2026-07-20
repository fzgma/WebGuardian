import streamlit as st

from scanner.scanner import scan
from ui.progress import create_progress_callback
from ui.result_view import render_scan_result
from ui.scan_config import render_scan_config, validate_scan_options


def run_app():
    """启动 Streamlit 页面。"""

    st.set_page_config(
        page_title="WebGuardian 网站安全检测工具",
        layout="centered"
    )

    st.title("WebGuardian 网站安全检测工具")
    st.caption("输入网站地址后，系统将进行基础安全检测并生成评分结果。")

    options = render_scan_config()

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

        validation_error = validate_scan_options(options)
        if validation_error:
            st.warning(validation_error)
            return

        on_progress = create_progress_callback()

        with st.spinner("正在检测，请稍候..."):
            result = scan(url, progress_callback=on_progress, options=options)


        if not result.get("ok"):
            st.error(f"检测失败：{result.get('error', '未知错误')}")
            return

        render_scan_result(result)


if __name__ == "__main__":
    run_app()

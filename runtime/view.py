"""扫描运行时的 Streamlit 展示。"""

from typing import Any

import streamlit as st

from ui.result.view import render_scan_result

from .models import RunStatus
from .runtime import get_scan_runtime, request_stop


@st.fragment(run_every=0.5)
def render_scan_runtime() -> None:
    """渲染扫描状态、停止按钮和结果。"""
    state = get_scan_runtime().snapshot()

    if state.status is RunStatus.RUNNING:
        st.progress(state.progress_percent)
        st.caption(f"{state.progress_text}（{state.progress_percent}%）")
        if not state.stop_requested:
            if st.button(
                "停止检测",
                type="secondary",
                use_container_width=True,
                key="stop_scan_button",
            ):
                request_stop()
                st.info("已请求停止检测，正在等待当前任务结束。")
        return

    if state.status is RunStatus.FINISHED and state.result:
        render_scan_result(state.result)
        return

    if state.status is RunStatus.STOPPED:
        st.warning("检测已停止")
        return

    if state.status is RunStatus.INVALID:
        st.warning(state.error)
        if state.error_hint:
            st.info(state.error_hint)
        if state.elapsed_seconds is not None:
            st.caption(f"检测耗时：{_format_elapsed_seconds(state.elapsed_seconds)}")
        return

    if state.status is RunStatus.ERROR:
        st.error(f"检测失败：{state.error}")
        if state.error_hint:
            st.info(state.error_hint)
        if state.elapsed_seconds is not None:
            st.caption(f"检测耗时：{_format_elapsed_seconds(state.elapsed_seconds)}")
        if state.error_detail and state.error_detail not in {
            state.error,
            state.error_hint,
        }:
            with st.expander("查看详细错误"):
                st.code(state.error_detail, wrap_lines=True)


def _format_elapsed_seconds(value: Any) -> str:
    """把耗时格式化为秒。"""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "未知"
    if seconds < 0:
        return "未知"
    return f"{seconds:.2f} 秒"

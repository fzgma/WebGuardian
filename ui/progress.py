import time
from collections.abc import Callable

import streamlit as st


def create_progress_callback() -> Callable[[int, str], None]:
    """创建节流的扫描进度回调。"""
    progress_bar = st.progress(0)
    progress_text = st.empty()
    progress_text.caption("准备开始检测")
    last_progress = {"percent": -1, "text": ""}
    last_update_at = {"ts": 0.0}

    def on_progress(percent: int, text: str) -> None:
        """更新扫描进度。"""
        now = time.monotonic()
        percent_changed = percent != last_progress["percent"]
        text_changed = text != last_progress["text"]
        elapsed = now - last_update_at["ts"]
        # 限制重绘频率，避免频繁更新页面。
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

    return on_progress

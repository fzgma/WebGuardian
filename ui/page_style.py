"""应用级页面样式。"""

import streamlit as st


def configure_page_width() -> None:
    """在宽屏布局下限制主内容宽度，保留居中的阅读重心。"""
    st.html(
        """
        <style>
        [data-testid="stMainBlockContainer"] {
            max-width: 1180px;
            margin-inline: auto;
            padding-inline: 2rem;
        }

        @media (max-width: 768px) {
            [data-testid="stMainBlockContainer"] {
                padding-inline: 1rem;
            }
        }
        </style>
        """
    )

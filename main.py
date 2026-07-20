from pathlib import Path

from streamlit.web.bootstrap import run


def start_app() -> None:
    """启动 Streamlit 应用。"""
    app_path = Path(__file__).parent / "ui" / "app.py"
    run(str(app_path), False, [], {})


if __name__ == "__main__":
    start_app()

"""UI 与后端边界测试。"""

from collections.abc import Callable
from typing import cast
from unittest.mock import MagicMock, call, patch

from result_model.models import ScanResult, TargetResult
from runtime.models import RunStatus, RuntimeSnapshot
from scanner.options import ScanOptions


def test_render_scan_result_can_render_same_result_repeatedly() -> None:
    """结果页应能稳定处理同一份扫描结果的重复渲染。"""
    from ui.result import view as view_module

    result = ScanResult(
        ok=True,
        target=TargetResult(
            url="https://example.com",
            normalized_url="https://example.com",
            host="example.com",
        ),
    )
    fake_streamlit = MagicMock()

    def columns(count: int, **_: object) -> tuple[MagicMock, ...]:
        return tuple(MagicMock() for _ in range(count))

    fake_streamlit.columns.side_effect = columns
    fake_streamlit.expander.return_value = MagicMock()
    fake_streamlit.tabs.return_value = tuple(MagicMock() for _ in range(4))

    with patch.object(view_module, "st", fake_streamlit):
        view_module.render_scan_result(result)
        view_module.render_scan_result(result)

    assert fake_streamlit.json.call_count == 2
    assert fake_streamlit.subheader.call_count >= 2
    fake_streamlit.tabs.assert_called_with(["概览", "基础检测", "页面风险", "原始数据"])
    assert call(2, gap="large") in fake_streamlit.columns.call_args_list
    rendered_raw = fake_streamlit.json.call_args.args[0]
    assert rendered_raw["ok"] is True
    assert rendered_raw["target"]["host"] == "example.com"


def test_render_module_durations_as_horizontal_bar_chart() -> None:
    """概览应将模块耗时渲染为横向条形图。"""
    from ui.result import view as view_module

    fake_streamlit = MagicMock()
    with patch.object(view_module, "st", fake_streamlit):
        view_module._render_module_durations({"DNS 安全检测": 0.42})

    fake_streamlit.bar_chart.assert_called_once_with(
        [{"检测模块": "DNS 安全检测", "耗时（秒）": 0.42}],
        x="检测模块",
        y="耗时（秒）",
        horizontal=True,
        color="#2A6F97",
    )


def test_message_summary_and_details_render_only_when_messages_exist() -> None:
    """概览仅在有错误或警告时显示计数与折叠详情。"""
    from ui.result import view as view_module

    fake_streamlit = MagicMock()
    fake_streamlit.expander.return_value = MagicMock()
    with patch.object(view_module, "st", fake_streamlit):
        view_module._render_message_summary([], [])
        view_module._render_messages([], [])

    assert fake_streamlit.mock_calls == []

    with patch.object(view_module, "st", fake_streamlit):
        view_module._render_message_summary(["TLS 超时"], ["DNS 使用备用记录"])
        view_module._render_messages(["TLS 超时"], ["DNS 使用备用记录"])

    fake_streamlit.error.assert_called_once_with("存在 1 项错误和 1 项警告，检测结果可能不完整。")
    assert any(
        call.args == ("检测过程提示（2）",)
        for call in fake_streamlit.expander.call_args_list
    )


def test_runtime_renders_finished_backend_result() -> None:
    """运行时完成后应将后端结果原样交给结果渲染器。"""
    from runtime import view as runtime_view

    result = ScanResult(ok=True, target=TargetResult(host="example.com"))
    snapshot = RuntimeSnapshot(
        status=RunStatus.FINISHED,
        progress_percent=100,
        progress_text="检测完成",
        result=result,
        error=None,
        error_hint=None,
        error_detail=None,
        error_kind=None,
        elapsed_seconds=1.2,
        stop_requested=False,
        running=False,
    )
    runtime = MagicMock()
    runtime.snapshot.return_value = snapshot

    with (
        patch.object(runtime_view, "get_scan_runtime", return_value=runtime),
        patch.object(runtime_view, "render_scan_result") as render_result,
    ):
        render_runtime = cast(Callable[[], None], getattr(runtime_view.render_scan_runtime, "__wrapped__"))
        render_runtime()

    render_result.assert_called_once_with(result)


def test_scan_form_passes_url_and_options_to_backend() -> None:
    """扫描表单应把用户输入 URL 和完整选项传给运行时。"""
    import app as app_module

    options = ScanOptions(
        check_https=True,
        check_ssl=False,
        check_dns_security=False,
        check_security_headers=True,
        check_trace=False,
        check_sensitive_paths=False,
        check_info_leak=True,
        check_page_scan=True,
        check_page_forms=True,
        page_scan_max_pages=7,
        page_scan_max_depth=3,
    )
    runtime = MagicMock()
    fake_streamlit = MagicMock()
    fake_streamlit.form.return_value = MagicMock()
    fake_streamlit.text_input.return_value = "https://example.com"
    fake_streamlit.form_submit_button.return_value = True

    with (
        patch.object(app_module, "st", fake_streamlit),
        patch.object(app_module, "get_scan_runtime", return_value=runtime),
        patch.object(app_module, "validate_input_url", return_value=(True, "")),
        patch.object(app_module, "collect_scan_options", return_value=options),
        patch.object(app_module, "validate_scan_options", return_value=None),
        patch.object(app_module, "start_scan", return_value=True) as start_scan,
    ):
        render_form = cast(Callable[[], None], getattr(app_module.render_scan_form, "__wrapped__"))
        render_form()

    runtime.clear_previous_result.assert_called_once_with()
    start_scan.assert_called_once_with("https://example.com", options)
    fake_streamlit.rerun.assert_called_once_with(scope="fragment")

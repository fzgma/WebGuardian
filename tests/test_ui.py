"""UI 与后端边界测试。"""

from collections.abc import Callable
from typing import cast
from unittest.mock import MagicMock, call, patch

import pytest
from pandas import DataFrame
from pandas import testing as pandas_testing
from streamlit.testing.v1 import AppTest

from result_model.composer import wrap_section_result
from result_model.models import JsonObject, ScanResult, ScoreItem, ScoreReport, SectionStatus, Summary, TargetResult
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


def _render_result_app(result: ScanResult) -> AppTest:
    """通过实际 Streamlit 组件验证结果页，不访问外部站点。"""
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from ui.result.view import render_scan_result\n"
        "render_scan_result(st.session_state['result'])\n",
        default_timeout=15,
    )
    app.session_state["result"] = result
    app.run()
    assert not app.exception
    return app


def _assert_frame_values(actual: DataFrame, expected: DataFrame) -> None:
    """比较完整表格内容，忽略 Streamlit Arrow 转换后的存储 dtype 差异。"""
    compare = cast(
        Callable[[DataFrame, DataFrame, bool], None],
        getattr(pandas_testing, "assert_frame_equal"),
    )
    compare(actual, expected, False)


@pytest.mark.parametrize(
    ("status", "label", "enabled_count", "unknown_count"),
    [("unknown", "待完成", 1, 1), ("partial", "待完成", 2, 1), ("not_applicable", "不适用", 0, 0)],
)
def test_incomplete_or_absent_score_never_renders_a_numeric_grade(
    status: str, label: str, enabled_count: int, unknown_count: int
) -> None:
    """未知、部分完成和无基础项必须保持可识别的非数值结论。"""
    report = ScoreReport(
        status=status,
        level=label,
        enabled_count=enabled_count,
        evaluated_count=max(0, enabled_count - unknown_count),
        unknown_count=unknown_count,
    )
    app = _render_result_app(ScanResult(ok=True, summary=Summary(scoring=report)))

    metrics = {item.label: item.value for item in app.metric}
    assert metrics["基础配置评分"] == label
    assert metrics["本次范围"] == f"{enabled_count}/7 项"
    captions = "\n".join(item.value for item in app.caption)
    assert f"未知 {unknown_count} 项" in captions
    assert "本次范围评级：" not in captions
    assert "None/100" not in str(metrics)


def test_https_only_full_score_displays_its_limited_scope_and_reason() -> None:
    """单项满分必须同时展示 1/7 范围及评分依据。"""
    report = ScoreReport(
        score=100, level="A级", status="complete", enabled_count=1,
        evaluated_count=1, earned_points=10, possible_points=10,
        items=[ScoreItem("https", "HTTPS", "passed", 10, 10, "最终响应使用 HTTPS。")],
    )
    result = ScanResult(
        ok=True,
        checks={"https": wrap_section_result("https", {"value": True}, enabled=True)},
        summary=Summary(score=100, level="A级", scoring=report),
    )
    app = _render_result_app(result)

    metrics = {item.label: item.value for item in app.metric}
    assert metrics["基础配置评分"] == "100/100"
    assert metrics["本次范围"] == "1/7 项"
    captions = "\n".join(item.value for item in app.caption)
    assert "已启用 1/7 项基础检查" in captions
    assert "页面风险独立展示，不直接计入基础配置评分。" in captions
    _assert_frame_values(
        app.dataframe[0].value,
        DataFrame([{"检测项": "HTTPS", "得分": "10", "满分": 10, "状态": "已通过", "原因": "最终响应使用 HTTPS。"}]),
    )


def test_invalid_header_value_is_visible_even_when_no_header_is_missing() -> None:
    """已有但无效的安全头不能因 missing 为空而显示成功。"""
    result = ScanResult(
        ok=True,
        checks={
            "security_headers": wrap_section_result(
                "security_headers",
                {
                    "score": 22, "missing": [],
                    "invalid": [{"header": "Strict-Transport-Security", "value": "max-age=0", "reason": "max-age 必须大于 0。"}],
                    "meta": {"assessment": "complete"},
                },
                enabled=True,
            )
        },
    )
    app = _render_result_app(result)

    assert any("安全响应头的值未通过基础校验" in item.value for item in app.warning)
    _assert_frame_values(
        app.dataframe[0].value,
        DataFrame([{"响应头": "Strict-Transport-Security", "当前值": "max-age=0", "原因": "max-age 必须大于 0。"}]),
    )
    assert not any("安全响应头" in item.value for item in app.success)


def test_unknown_empty_paths_shows_failed_observations_without_success() -> None:
    """所有路径请求失败的空列表必须展示未知及失败证据。"""
    payload: JsonObject = {
        "paths": [], "checked_count": 0, "failed_count": 1, "total_count": 1,
        "meta": {"assessment": "unknown"},
        "observations": [{"path": "/admin", "status": "error", "status_code": None, "reason": "请求超时"}],
    }
    result = ScanResult(
        ok=True,
        checks={
            "sensitive_paths": wrap_section_result(
                "sensitive_paths",
                payload,
                enabled=True,
            )
        },
    )
    app = _render_result_app(result)

    assert any("敏感路径检测尚未完成" in item.value for item in app.warning)
    assert any("已响应 0 / 1，失败 1" in item.value for item in app.caption)
    assert not any("敏感路径" in item.value for item in app.success)
    _assert_frame_values(
        app.dataframe[0].value,
        DataFrame([{"路径": "/admin", "状态": "请求失败", "响应码": "未知", "原因": "请求超时", "跳转目标": ""}]),
    )


def test_suspected_path_exposure_has_a_readable_observation_status() -> None:
    """真实路径检测的 suspected_exposure 状态应显示为疑似暴露。"""
    payload: JsonObject = {
        "paths": ["/admin"], "checked_count": 1, "failed_count": 0, "total_count": 1,
        "meta": {"assessment": "complete"},
        "observations": [{"path": "/admin", "status": "suspected_exposure", "status_code": 200, "reason": "路径返回成功响应，需要人工确认。"}],
    }
    result = ScanResult(
        ok=True,
        checks={
            "sensitive_paths": wrap_section_result(
                "sensitive_paths",
                payload,
                enabled=True,
            )
        },
    )
    app = _render_result_app(result)

    _assert_frame_values(
        app.dataframe[0].value,
        DataFrame([{"路径": "/admin", "状态": "疑似暴露", "响应码": "200", "原因": "路径返回成功响应，需要人工确认。", "跳转目标": ""}]),
    )
    assert any("发现可能存在的敏感路径" in item.value for item in app.warning)


def test_tls_for_http_target_is_not_applicable_instead_of_unknown() -> None:
    """最终为 HTTP 的目标应说明 TLS 不适用，不能提示证据获取失败。"""
    result = ScanResult(
        ok=True,
        checks={
            "https": wrap_section_result("https", {"value": False}, enabled=True),
            "tls": wrap_section_result(
                "tls", {"ssl_valid": None, "meta": {"assessment": "not_applicable"}},
                enabled=True, status=SectionStatus.SKIPPED,
            ),
        },
    )
    app = _render_result_app(result)

    assert any("TLS/SSL 检测不适用：最终访问地址未使用 HTTPS。" == item.value for item in app.info)
    assert not any("尚未取得有效的证书检测结论" in item.value for item in app.info)
    assert not any("SSL 证书有效" in item.value for item in app.markdown)


def test_failed_page_requests_are_not_presented_as_checked_pages() -> None:
    """页面失败与跳过单独显示，不能用零发现宣告检查成功。"""
    result = ScanResult(
        ok=True,
        checks={
            "page_scan": wrap_section_result(
                "page_scan",
                {
                    "enabled": True, "pages_attempted": 2, "pages_scanned": 0,
                    "pages_failed": 1, "pages_skipped": 1, "max_pages": 10,
                    "assessment": "unknown", "findings": [],
                },
                enabled=True,
            )
        },
    )
    app = _render_result_app(result)

    output = "\n".join(item.value for item in app.markdown)
    assert "完成 HTML 检查 0 页，失败 1 页，跳过 1 页" in output
    assert any("页面检查未形成完整结论" in item.value for item in app.info)
    assert not any("页面级安全问题" in item.value for item in app.success)

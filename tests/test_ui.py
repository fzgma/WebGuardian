"""UI 与后端边界测试。"""

import unittest
from collections.abc import Callable
from typing import cast
from unittest.mock import MagicMock, patch

from scanner.options import ScanOptions
from result_model.models import ScanResult, TargetResult


class UiBoundaryTests(unittest.TestCase):
    """验证 UI 结果渲染和扫描参数传递。"""

    def test_render_scan_result_can_render_same_result_repeatedly(self) -> None:
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

        def columns(count: int) -> tuple[MagicMock, ...]:
            """创建测试用的 Streamlit 列对象。"""
            return tuple(MagicMock() for _ in range(count))

        fake_streamlit.columns.side_effect = columns
        fake_streamlit.expander.return_value = MagicMock()

        with patch.object(view_module, "st", fake_streamlit):
            view_module.render_scan_result(result)
            view_module.render_scan_result(result)

        self.assertEqual(fake_streamlit.json.call_count, 2)
        self.assertGreaterEqual(fake_streamlit.subheader.call_count, 2)
        rendered_raw = fake_streamlit.json.call_args.args[0]
        self.assertEqual(rendered_raw["ok"], True)
        self.assertEqual(rendered_raw["target"]["host"], "example.com")

    def test_scan_form_passes_url_and_options_to_backend(self) -> None:
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
        fake_form = MagicMock()
        fake_streamlit.form.return_value = fake_form
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
            render_form = cast(
                Callable[[], None], getattr(app_module.render_scan_form, "__wrapped__")
            )
            render_form()

        runtime.clear_previous_result.assert_called_once_with()
        start_scan.assert_called_once_with("https://example.com", options)
        fake_streamlit.rerun.assert_called_once_with(scope="fragment")


if __name__ == "__main__":
    unittest.main()

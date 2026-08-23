"""扫描结果模型、转换和展示。"""

from .composer import (
    build_result_view_model,
    build_target_result,
    compose_scan_error,
    compose_scan_result,
    get_section,
    summarize_page_scan,
    wrap_section_result,
)
from .view import render_scan_result
from .models import (
    Messages,
    ScanContext,
    ScanResult,
    ScanViewModel,
    SectionResult,
    Summary,
    TargetResult,
)

__all__ = [
    "build_result_view_model",
    "build_target_result",
    "compose_scan_error",
    "compose_scan_result",
    "get_section",
    "render_scan_result",
    "summarize_page_scan",
    "wrap_section_result",
    "Messages",
    "ScanContext",
    "ScanResult",
    "ScanViewModel",
    "SectionResult",
    "Summary",
    "TargetResult",
]

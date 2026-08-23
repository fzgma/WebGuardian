"""扫描运行时模块。"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import RunStatus, RuntimeSnapshot
    from .runtime import ScanRuntime, get_scan_runtime, request_stop, start_scan
    from .view import render_scan_runtime

__all__ = [
    "RunStatus",
    "RuntimeSnapshot",
    "ScanRuntime",
    "get_scan_runtime",
    "request_stop",
    "render_scan_runtime",
    "start_scan",
]


def __getattr__(name: str) -> object:
    """按需加载运行时公开入口，避免扫描模块导入时形成循环。"""
    if name in {"RunStatus", "RuntimeSnapshot"}:
        from .models import RunStatus, RuntimeSnapshot

        if name == "RunStatus":
            return RunStatus
        return RuntimeSnapshot
    if name in {"ScanRuntime", "get_scan_runtime", "request_stop", "start_scan"}:
        from .runtime import ScanRuntime, get_scan_runtime, request_stop, start_scan

        if name == "ScanRuntime":
            return ScanRuntime
        if name == "get_scan_runtime":
            return get_scan_runtime
        if name == "request_stop":
            return request_stop
        return start_scan
    if name == "render_scan_runtime":
        from .view import render_scan_runtime

        return render_scan_runtime
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""扫描运行时的启动与停止测试。"""

from threading import Event
from unittest.mock import patch

from runtime import runtime as runtime_module
from runtime.models import RunStatus
from scanner.options import ScanOptions
from utils.control import ScanInterrupted


def test_runtime_starts_rejects_duplicate_start_and_stops() -> None:
    """运行时应启动后台任务、拒绝并发启动，并在停止后清理结果。"""
    scan_started = Event()

    def blocking_scan(
        _url: str,
        *,
        progress_callback: object,
        options: ScanOptions,
        stop_event: Event,
    ) -> object:
        scan_started.set()
        assert stop_event.wait(timeout=1)
        raise ScanInterrupted("检测已停止")

    runtime = runtime_module.ScanRuntime()
    with patch.object(runtime_module, "scan", side_effect=blocking_scan):
        assert runtime.start("https://example.com", ScanOptions()) is True
        assert scan_started.wait(timeout=1)
        assert runtime.snapshot().status is RunStatus.RUNNING
        assert runtime.start("https://example.com", ScanOptions()) is False

        runtime.request_stop()
        thread = runtime.thread
        assert thread is not None
        thread.join(timeout=1)

    snapshot = runtime.snapshot()
    assert thread.is_alive() is False
    assert snapshot.status is RunStatus.STOPPED
    assert snapshot.stop_requested is True
    assert snapshot.result is None
    assert snapshot.progress_text == "检测已停止"

"""扫描后台运行时与控制入口。"""

import threading
from dataclasses import dataclass, field

import streamlit as st

from scanner.options import ScanOptions
from scanner.scanner import scan
from ui.result.models import ScanResult
from utils.control import ScanInterrupted
from utils.timer import Timer

from .errors import ScanErrorInfo, explain_scan_error
from .models import RunStatus, RuntimeSnapshot


@dataclass
class ScanRuntime:
    """保存一次扫描的后台状态。"""

    status: RunStatus = RunStatus.IDLE
    progress_percent: int = 0
    progress_text: str = "准备开始检测"
    result: ScanResult | None = None
    error: str | None = None
    error_hint: str | None = None
    error_detail: str | None = None
    error_kind: str | None = None
    elapsed_seconds: float | None = None
    stop_requested: bool = False
    stop_event: threading.Event = field(
        default_factory=threading.Event, repr=False, compare=False
    )
    thread: threading.Thread | None = field(default=None, repr=False, compare=False)
    lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def is_running(self) -> bool:
        """判断扫描是否仍在运行。"""
        with self.lock:
            return (
                self.status is RunStatus.RUNNING
                and self.thread is not None
                and self.thread.is_alive()
            )

    def start(self, url: str, options: ScanOptions) -> bool:
        """启动后台扫描任务。"""
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                return False

            self._reset_for_new_scan()
            self.thread = threading.Thread(
                target=self._run,
                args=(url, options, self.stop_event),
                daemon=True,
            )
            thread = self.thread

        thread.start()
        return True

    def clear_previous_result(self) -> None:
        """清空上一次扫描的结果展示。"""
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                return
            self.status = RunStatus.IDLE
            self.progress_percent = 0
            self.progress_text = "准备开始检测"
            self.stop_requested = False
            self._reset_display_state()

    def _reset_for_new_scan(self) -> None:
        """重置状态并准备启动新扫描。"""
        self.status = RunStatus.RUNNING
        self.progress_percent = 0
        self.progress_text = "正在准备检测"
        self.stop_requested = False
        self.stop_event = threading.Event()
        self._reset_display_state()

    def _reset_display_state(self) -> None:
        """清空结果和错误展示。"""
        self.result = None
        self.error = None
        self.error_hint = None
        self.error_detail = None
        self.error_kind = None
        self.elapsed_seconds = None

    def request_stop(self) -> None:
        """请求停止当前扫描。"""
        with self.lock:
            self.stop_requested = True
            self.progress_text = "正在停止检测"
            self.stop_event.set()

    def snapshot(self) -> RuntimeSnapshot:
        """复制当前状态给界面渲染。"""
        with self.lock:
            return RuntimeSnapshot(
                status=self.status,
                progress_percent=self.progress_percent,
                progress_text=self.progress_text,
                result=self.result,
                error=self.error,
                error_hint=self.error_hint,
                error_detail=self.error_detail,
                error_kind=self.error_kind,
                elapsed_seconds=self.elapsed_seconds,
                stop_requested=self.stop_requested,
                running=self.thread is not None and self.thread.is_alive(),
            )

    def _set_error(self, raw_error: str) -> ScanErrorInfo:
        """把原始错误转换成友好的展示信息。"""
        info = explain_scan_error(raw_error)
        self.error = info.summary
        self.error_hint = info.hint
        self.error_detail = info.detail
        self.error_kind = info.kind
        return info

    def _run(self, url: str, options: ScanOptions, stop_event: threading.Event) -> None:
        """在线程中执行扫描并记录结果。"""
        timer = Timer()
        try:
            result = scan(
                url,
                progress_callback=self.on_progress,
                options=options,
                stop_event=stop_event,
            )
        except ScanInterrupted:
            with self.lock:
                # 停止后清空结果，只保留停止状态。
                self.status = RunStatus.STOPPED
                self.progress_percent = 0
                self.progress_text = "检测已停止"
                self.result = None
                self.error = None
                self.error_hint = None
                self.error_detail = None
                self.error_kind = None
                self.elapsed_seconds = round(timer.elapsed_seconds(), 2)
            return
        except Exception as exc:  # 捕获所有异常，避免线程崩溃
            with self.lock:
                info = self._set_error(f"{type(exc).__name__}: {exc}")
                self.status = (
                    RunStatus.INVALID
                    if info.kind == "validation"
                    else RunStatus.ERROR
                )
                self.elapsed_seconds = round(timer.elapsed_seconds(), 2)
            return

        with self.lock:
            if result.ok:
                self.status = RunStatus.FINISHED
                self.result = result
                self.elapsed_seconds = result.summary.elapsed_seconds
                self.progress_percent = 100
                self.progress_text = "检测完成"
            else:
                info = self._set_error(result.error or "检测失败")
                self.status = (
                    RunStatus.INVALID
                    if info.kind == "validation"
                    else RunStatus.ERROR
                )
                self.elapsed_seconds = result.summary.elapsed_seconds

    def on_progress(self, percent: int, text: str) -> None:
        """记录扫描进度。"""
        with self.lock:
            # 进度回调只负责覆盖最新状态。
            self.progress_percent = max(0, min(100, percent))
            self.progress_text = text


def get_scan_runtime() -> ScanRuntime:
    """获取当前会话的扫描运行状态。"""
    if "scan_runtime" not in st.session_state:
        st.session_state["scan_runtime"] = ScanRuntime()
    return st.session_state["scan_runtime"]


def start_scan(url: str, options: ScanOptions) -> bool:
    """启动一次新的扫描。"""
    return get_scan_runtime().start(url, options)


def request_stop() -> None:
    """请求停止当前扫描。"""
    get_scan_runtime().request_stop()

"""扫描控制与中断信号。"""

from threading import Event


class ScanInterrupted(RuntimeError):
    """扫描被用户中断。"""


def check_stop(stop_event: Event | None) -> None:
    """在需要时抛出中断异常。"""
    if stop_event is not None and stop_event.is_set():
        raise ScanInterrupted("检测已停止")

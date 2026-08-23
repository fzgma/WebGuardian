"""扫描运行时模型。"""

from dataclasses import dataclass
from enum import Enum

from ui.result.models import ScanResult


class RunStatus(str, Enum):
    """一次扫描任务的运行状态。"""

    IDLE = "idle"
    RUNNING = "running"
    FINISHED = "finished"
    STOPPED = "stopped"
    INVALID = "invalid"
    ERROR = "error"


@dataclass(frozen=True)
class RuntimeSnapshot:
    """提供给界面的扫描运行时快照。"""

    status: RunStatus
    progress_percent: int
    progress_text: str
    result: ScanResult | None
    error: str | None
    error_hint: str | None
    error_detail: str | None
    error_kind: str | None
    elapsed_seconds: float | None
    stop_requested: bool
    running: bool

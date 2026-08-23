"""计时工具。"""

from time import perf_counter


class Timer:
    """简单的单次计时器。"""

    def __init__(self) -> None:
        """从当前时间开始计时。"""
        self._start = perf_counter()

    def reset(self) -> None:
        """重新开始计时。"""
        self._start = perf_counter()

    def elapsed_seconds(self) -> float:
        """返回已过去的秒数。"""
        return perf_counter() - self._start

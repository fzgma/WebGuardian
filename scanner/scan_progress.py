"""扫描进度计算。"""

from collections.abc import Callable

from .options import ScanOptions


class ScanProgress:
    """按扫描工作量汇报进度。"""

    def __init__(
        self,
        options: ScanOptions,
        sensitive_path_count: int,
        callback: Callable[[int, str], None] | None,
    ) -> None:
        """初始化扫描进度。"""
        self.callback = callback
        self.completed_work = 0
        self.total_work = _total_work(options, sensitive_path_count)

    def update(self, text: str, work_units: int = 0) -> None:
        """完成工作并汇报进度。"""
        self.completed_work += work_units
        if self.callback:
            percent = 100 if self.completed_work >= self.total_work else round(
                self.completed_work / self.total_work * 100
            )
            self.callback(percent, text)

    def page_callback(self, options: ScanOptions) -> Callable[[int, str], None]:
        """创建页面扫描进度回调。"""
        page_work = _page_work(options)
        page_start = self.completed_work

        def update_page(percent: int, text: str) -> None:
            """映射页面扫描的局部进度。"""
            if self.callback:
                completed = page_start + round(page_work * percent / 100)
                overall = min(99, round(completed / self.total_work * 100))
                self.callback(overall, text)

        return update_page

    def complete_page_scan(self, options: ScanOptions) -> None:
        """完成页面级扫描工作量。"""
        self.update("页面级安全检查完成", _page_work(options))


def _page_work(options: ScanOptions) -> int:
    """计算页面级扫描工作量。"""
    checks = sum(
        (
            options.check_page_redirects,
            options.check_page_headers,
            options.check_page_cookie_flags,
            options.check_page_mixed_content,
            options.check_page_forms,
            options.check_page_exposed_info,
        )
    )
    return options.page_scan_max_pages * (1 + checks)


def _total_work(options: ScanOptions, sensitive_path_count: int) -> int:
    """计算当前扫描总工作量。"""
    total = 1 + sum(
        (
            options.check_https,
            options.check_ssl,
            options.check_security_headers,
            options.check_info_leak,
            options.check_trace,
        )
    )
    if options.check_sensitive_paths:
        total += sensitive_path_count
    if options.check_page_scan:
        total += _page_work(options)
    return total + 1

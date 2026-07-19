from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class ScanOptions:
    """保存一次扫描的开关配置。"""
    check_https: bool = True
    check_ssl: bool = True
    check_security_headers: bool = True
    check_trace: bool = True
    check_sensitive_paths: bool = True
    check_info_leak: bool = True
    check_page_scan: bool = False
    check_page_mixed_content: bool = False
    check_page_forms: bool = False
    check_page_cookie_flags: bool = False
    check_page_redirects: bool = False
    check_page_headers: bool = False
    check_page_exposed_info: bool = False
    page_scan_max_pages: int = 10
    page_scan_max_depth: int = 2

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "ScanOptions":
        """从字典构建扫描配置。"""
        if not data:
            return cls()

        return cls(
            check_https=bool(data.get("check_https", True)),
            check_ssl=bool(data.get("check_ssl", True)),
            check_security_headers=bool(data.get("check_security_headers", True)),
            check_trace=bool(data.get("check_trace", True)),
            check_sensitive_paths=bool(data.get("check_sensitive_paths", True)),
            check_info_leak=bool(data.get("check_info_leak", True)),
            check_page_scan=bool(data.get("check_page_scan", False)),
            check_page_mixed_content=bool(data.get("check_page_mixed_content", False)),
            check_page_forms=bool(data.get("check_page_forms", False)),
            check_page_cookie_flags=bool(data.get("check_page_cookie_flags", False)),
            check_page_redirects=bool(data.get("check_page_redirects", False)),
            check_page_headers=bool(data.get("check_page_headers", False)),
            check_page_exposed_info=bool(data.get("check_page_exposed_info", False)),
            page_scan_max_pages=int(data.get("page_scan_max_pages", 10) or 10),
            page_scan_max_depth=int(data.get("page_scan_max_depth", 2) or 2),
        )

    def to_dict(self) -> Dict[str, Any]:
        """导出扫描配置。"""
        return asdict(self)

    def enabled_items(self) -> int:
        """统计当前启用的检测项数量。"""
        page_flags = (
            self.check_page_mixed_content,
            self.check_page_forms,
            self.check_page_cookie_flags,
            self.check_page_redirects,
            self.check_page_headers,
            self.check_page_exposed_info,
        )

        count = sum(
            (
                self.check_https,
                self.check_ssl,
                self.check_security_headers,
                self.check_trace,
                self.check_sensitive_paths,
                self.check_info_leak,
            )
        )

        if self.check_page_scan:
            count += 1 + sum(page_flags)

        return count

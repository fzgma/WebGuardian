from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class ScanOptions:
    check_https: bool = True
    check_ssl: bool = True
    check_security_headers: bool = True
    check_trace: bool = True
    check_sensitive_paths: bool = True
    check_ports: bool = True
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
        if not data:
            return cls()

        return cls(
            check_https=bool(data.get("check_https", True)),
            check_ssl=bool(data.get("check_ssl", True)),
            check_security_headers=bool(data.get("check_security_headers", True)),
            check_trace=bool(data.get("check_trace", True)),
            check_sensitive_paths=bool(data.get("check_sensitive_paths", True)),
            check_ports=bool(data.get("check_ports", True)),
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
        return asdict(self)

    def enabled_items(self) -> int:
        count = sum(
            1
            for flag in (
                self.check_https,
                self.check_ssl,
                self.check_security_headers,
                self.check_trace,
                self.check_sensitive_paths,
                self.check_ports,
                self.check_info_leak,
            )
            if flag
        )
        if self.check_page_scan:
            count += 1
            count += sum(
                1
                for flag in (
                    self.check_page_mixed_content,
                    self.check_page_forms,
                    self.check_page_cookie_flags,
                    self.check_page_redirects,
                    self.check_page_headers,
                    self.check_page_exposed_info,
                )
                if flag
            )
        return count

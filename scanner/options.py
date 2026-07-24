from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields, is_dataclass
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
    check_page_sitecheck: bool = False
    page_scan_max_pages: int = 10
    page_scan_max_depth: int = 2

    @classmethod
    def from_dict(cls, data: Any = None) -> "ScanOptions": #data是any类型，可能是字典、dataclass实例、其他对象等
        """从字典构建扫描配置。"""
        if not data:
            return cls()
        
        """
        Streamlit 热更新后，session_state 里可能还留着旧版本的 ScanOptions 实例。
        这时直接做 isinstance 判断不稳定，所以这里把“当前实例、旧实例、dataclass、字典
        和其他带同名属性的对象”都收敛成统一的 Mapping，再按字段名读取，避免源码修改后
        因对象类型漂移导致抛AttributeError异常。
        """

        if isinstance(data, cls):
            return data

        if hasattr(data, "to_dict"):
            try:
                data = data.to_dict()
            except Exception:
                data = data

        if is_dataclass(data) and not isinstance(data, type):
            data = asdict(data)

        if not isinstance(data, Mapping):
            data = {field.name: getattr(data, field.name, None) for field in fields(cls)}

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
            check_page_sitecheck=bool(data.get("check_page_sitecheck", False)),
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
            self.check_page_sitecheck,
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

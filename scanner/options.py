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
        )

    def to_dict(self) -> Dict[str, bool]:
        return asdict(self)

    def enabled_items(self) -> int:
        return sum(self.to_dict().values())

"""基础站点扫描模块。"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base_checks import SENSITIVE_PATHS, run_base_checks
    from .dns import run_dns_check
    from .tls import run_tls_check

__all__ = ["SENSITIVE_PATHS", "run_base_checks", "run_dns_check", "run_tls_check"]


def __getattr__(name: str) -> object:
    """按需加载基础扫描入口，避免子模块导入时形成循环。"""
    if name in {"SENSITIVE_PATHS", "run_base_checks"}:
        from .base_checks import SENSITIVE_PATHS, run_base_checks

        if name == "SENSITIVE_PATHS":
            return SENSITIVE_PATHS
        return run_base_checks
    if name == "run_dns_check":
        from .dns import run_dns_check

        return run_dns_check
    if name == "run_tls_check":
        from .tls import run_tls_check

        return run_tls_check
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

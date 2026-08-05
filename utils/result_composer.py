"""扫描结果构造与合成工具。"""

from collections.abc import Iterable, Mapping
from typing import Any


def build_target_result(
    input_url: str,
    normalized_url: str,
    host: str,
    resolved_ips: list[str],
) -> dict[str, Any]:
    """构造目标信息结果。"""
    return {
        "input_url": input_url,
        "normalized_url": normalized_url,
        "url": normalized_url,
        "host": host,
        "resolved_ips": list(resolved_ips),
    }


def wrap_section_result(
    name: str,
    payload: Mapping[str, Any] | None = None,
    *,
    enabled: bool | None = None,
    status: str = "ok",
    summary: str = "",
    warnings: Iterable[str] | None = None,
    findings: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """把模块原始结果包装成统一结构。"""
    result = dict(payload or {})
    result["name"] = name
    result["enabled"] = enabled
    result["status"] = status
    result["summary"] = summary
    result.setdefault("meta", {})

    if warnings is None:
        result.setdefault("warnings", [])
    else:
        result["warnings"] = list(warnings)

    if findings is None:
        result.setdefault("findings", [])
    else:
        result["findings"] = list(findings)

    return result


def get_section(result: Mapping[str, Any], name: str, default: Any = None) -> Any:
    """从统一结果里取出某个扫描 section。"""
    checks = result.get("checks", {})
    if isinstance(checks, Mapping):
        return checks.get(name, default)
    return default


def build_result_view_model(result: Mapping[str, Any]) -> dict[str, Any]:
    """把扫描大结果转换成展示层使用的稳定视图模型。"""
    summary = result.get("summary", {})
    target = result.get("target", {})
    if not isinstance(summary, Mapping):
        summary = {}
    if not isinstance(target, Mapping):
        target = {}

    section_names = (
        "https",
        "tls",
        "dns_security",
        "security_headers",
        "http_methods",
        "sensitive_paths",
        "info_leak",
        "page_scan",
    )
    sections = {
        name: _mapping_or_empty(get_section(result, name, {}))
        for name in section_names
    }
    page_scan_summary = summary.get("page_scan_summary", {})
    if not isinstance(page_scan_summary, Mapping):
        page_scan_summary = {}

    return {
        "overview": {
            "score": summary.get("score", 0),
            "level": summary.get("level", "未知"),
            "elapsed_seconds": summary.get("elapsed_seconds"),
            "https": sections["https"],
            "page_scan": dict(page_scan_summary),
        },
        "target": dict(target),
        "sections": sections,
        "messages": {
            "errors": list(result.get("errors", []) or []),
            "warnings": list(result.get("warnings", []) or []),
        },
        "raw": result,
    }


def summarize_page_scan(page_scan: Mapping[str, Any] | None) -> dict[str, Any]:
    """把页面扫描结果压缩成概览。"""
    if not page_scan:
        return {
            "enabled": False,
            "pages_scanned": 0,
            "finding_count": 0,
            "risk_counts": {"低": 0, "中": 0, "高": 0},
            "highest_risk": "无",
        }

    return {
        "enabled": bool(page_scan.get("enabled")),
        "pages_scanned": page_scan.get("pages_scanned", 0),
        "finding_count": page_scan.get("finding_count", 0),
        "risk_counts": page_scan.get("risk_counts", {"低": 0, "中": 0, "高": 0}),
        "highest_risk": page_scan.get("highest_risk", "无"),
    }


def compose_scan_result(
    *,
    target: Mapping[str, Any],
    checks: Mapping[str, Any],
    score: int,
    level: str,
    elapsed_seconds: float,
    page_scan: Mapping[str, Any] | None = None,
    errors: Iterable[str] | None = None,
    warnings: Iterable[str] | None = None,
) -> dict[str, Any]:
    """合成最终的大结果。"""
    error_list = _unique_texts(errors or [])
    warning_list = _unique_texts(warnings or [])
    warning_list.extend(_collect_section_warnings(checks))
    warning_list = _unique_texts(warning_list)
    page_summary = summarize_page_scan(page_scan)
    return {
        "ok": True,
        "target": dict(target),
        "checks": dict(checks),
        "summary": {
            "score": score,
            "level": level,
            "elapsed_seconds": elapsed_seconds,
            "page_scan_summary": page_summary,
        },
        "errors": error_list,
        "warnings": warning_list,
    }


def compose_scan_error(message: str, elapsed_seconds: float) -> dict[str, Any]:
    """构造统一的扫描失败结果。"""
    return {
        "ok": False,
        "error": message,
        "summary": {"elapsed_seconds": elapsed_seconds},
        "errors": [message],
        "warnings": [],
    }


def _unique_texts(values: Iterable[Any]) -> list[str]:
    """对字符串列表去重并保持顺序。"""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _collect_section_warnings(checks: Mapping[str, Any]) -> list[str]:
    """聚合各 section 的 warning。"""
    warnings: list[str] = []
    for section in checks.values():
        if not isinstance(section, Mapping):
            continue
        warnings.extend(section.get("warnings", []) or [])
    return _unique_texts(warnings)


def _mapping_or_empty(value: Any) -> dict[str, Any]:
    """把可选 section 归一化为字典，避免展示层处理 None。"""
    return dict(value) if isinstance(value, Mapping) else {}

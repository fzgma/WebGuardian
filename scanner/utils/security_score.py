"""安全评分规则。"""

from typing import Any, Dict, Tuple

from ..options import ScanOptions


def calculate_score(result: Dict[str, Any], options: ScanOptions) -> Tuple[int, str]:
    """计算安全评分和等级。"""
    score = 0
    max_score = 0

    if options.check_https:
        max_score += 10
        if result.get("https"):
            score += 10

    if options.check_ssl:
        max_score += 20
        if result.get("ssl_valid"):
            score += 10
        if isinstance(result.get("ssl_days_left"), int) and result["ssl_days_left"] > 7:
            score += 10

    if options.check_security_headers:
        max_score += 30
        score += result.get("security_header_score", 0) or 0

    if options.check_info_leak:
        max_score += 20
        info_leak = result.get("info_leak", {})
        score += 10 if info_leak.get("version_exposed") is False else 0
        score += 10 if info_leak.get("framework_exposed") is False else 0

    if options.check_trace:
        max_score += 10
        score += 10 if result.get("trace_enabled") is False else 0

    if options.check_sensitive_paths:
        max_score += 10
        score += 10 if not result.get("sensitive_paths") else 0

    score = round(score / max_score * 100) if max_score else 0
    return score, _security_level(score)


def _security_level(score: int) -> str:
    """返回安全等级。"""
    if score >= 85:
        return "A级"
    if score >= 70:
        return "B级"
    return "C级"

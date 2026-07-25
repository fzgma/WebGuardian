"""安全评分规则。"""

from typing import Any, Dict, Tuple

from scanner.options import ScanOptions

_SECURITY_HEADERS_MAX = 30
_INFO_LEAK_WEIGHTS = {
    "version_exposed": 4,
    "framework_exposed": 3,
    "meta_exposed": 3,
}
_DNS_SECURITY_MAX = 15
_HTTP_METHOD_MAX = 5
_TLS_MAX = 20


def calculate_score(result: Dict[str, Any], options: ScanOptions) -> Tuple[int, str]:
    """计算安全评分和等级。"""
    score = 0
    max_score = 0

    if options.check_https:
        max_score += 10
        if result.get("https"):
            score += 10

    if options.check_ssl:
        max_score += _TLS_MAX
        score += _tls_score(result.get("tls", {}), result)

    if options.check_dns_security:
        dns_security = result.get("dns_security", {})
        if dns_security.get("status") != "skipped":
            max_score += _DNS_SECURITY_MAX
            score += _dns_security_score(dns_security)

    if options.check_security_headers:
        max_score += _SECURITY_HEADERS_MAX
        score += result.get("security_header_score", 0) or 0

    if options.check_info_leak:
        max_score += 10
        info_leak = result.get("info_leak", {})
        for field, weight in _INFO_LEAK_WEIGHTS.items():
            score += weight if info_leak.get(field) is False else 0

    if options.check_trace:
        max_score += _HTTP_METHOD_MAX
        method_info = result.get("http_methods", {})
        trace_enabled = method_info.get("trace_enabled") if method_info else result.get("trace_enabled")
        exposed_methods = method_info.get("exposed_methods", []) if method_info else []
        if trace_enabled is False and not exposed_methods:
            score += _HTTP_METHOD_MAX

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


def _tls_score(tls_info: Dict[str, Any], result: Dict[str, Any]) -> int:
    """计算 TLS 配置得分。"""
    if not tls_info:
        return 0

    score = 0
    ssl_valid = tls_info.get("ssl_valid")
    if ssl_valid is None:
        ssl_valid = result.get("ssl_valid")

    if ssl_valid:
        score += 8

    days_left = tls_info.get("ssl_days_left")
    if days_left is None:
        days_left = result.get("ssl_days_left")
    if isinstance(days_left, int) and days_left > 7:
        score += 4

    supported_protocols = tls_info.get("supported_protocols", [])
    weak_protocols = tls_info.get("weak_protocols", [])
    if supported_protocols and not weak_protocols and all(proto in {"TLS 1.2", "TLS 1.3"} for proto in supported_protocols):
        score += 4
    elif supported_protocols and not weak_protocols:
        score += 2

    if tls_info.get("cipher_weak") is False:
        score += 2

    if tls_info.get("chain_complete") is True or tls_info.get("chain_verified") is True:
        score += 2

    return min(score, _TLS_MAX)


def _dns_security_score(dns_security: Dict[str, Any]) -> int:
    """计算 DNS 安全检测得分。"""
    score = 0

    spf = dns_security.get("spf", {})
    spf_policy = spf.get("policy")
    if spf_policy == "strict":
        score += 5
    elif spf_policy == "softfail":
        score += 3

    dmarc = dns_security.get("dmarc", {})
    dmarc_policy = dmarc.get("policy")
    if dmarc_policy == "reject":
        score += 5
    elif dmarc_policy == "quarantine":
        score += 3

    caa = dns_security.get("caa", {})
    if caa.get("present") and caa.get("issuers"):
        score += 5
    elif caa.get("present"):
        score += 2

    return min(score, _DNS_SECURITY_MAX)

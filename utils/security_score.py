"""安全评分规则。"""

from typing import Any, Dict, Tuple

from scanner.options import ScanOptions
from utils.result_composer import get_section

_HTTPS_MAX = 10
_SECURITY_HEADERS_MAX = 30
_INFO_LEAK_WEIGHTS = {
    "version_exposed": 4,
    "framework_exposed": 3,
    "meta_exposed": 3,
}
_DNS_SECURITY_MAX = 15
_HTTP_TRACE_MAX = 3
_HTTP_EXPOSED_METHODS_MAX = 2
_HTTP_METHOD_MAX = _HTTP_TRACE_MAX + _HTTP_EXPOSED_METHODS_MAX
_SENSITIVE_PATHS_MAX = 10
_TLS_MAX = 20


def calculate_score(result: Dict[str, Any], options: ScanOptions) -> Tuple[int, str]:
    """按已启用的站点检查计算归一化评分。

    页面级扫描是附加风险信息，不计入站点安全总分，避免扫描深度影响基础评分。
    """
    score = 0
    max_score = 0

    https = get_section(result, "https", {})
    if options.check_https and https.get("enabled") is True:
        max_score += _HTTPS_MAX
        if https.get("value") is True:
            score += _HTTPS_MAX

    tls = get_section(result, "tls", {})
    if options.check_ssl and tls.get("enabled") is True:
        max_score += _TLS_MAX
        score += _tls_score(tls)

    dns_security = get_section(result, "dns_security", {})
    if (
        options.check_dns_security
        and dns_security.get("enabled") is True
        and dns_security.get("status") != "skipped"
    ):
        max_score += _DNS_SECURITY_MAX
        score += _dns_security_score(dns_security)

    security_headers = get_section(result, "security_headers", {})
    if options.check_security_headers and security_headers.get("enabled") is True:
        max_score += _SECURITY_HEADERS_MAX
        score += security_headers.get("score", 0) or 0

    if options.check_info_leak:
        info_leak = get_section(result, "info_leak", {})
        if info_leak.get("enabled") is True:
            max_score += 10
        else:
            info_leak = {}
        for field, weight in _INFO_LEAK_WEIGHTS.items():
            score += weight if info_leak.get(field) is False else 0

    method_info = get_section(result, "http_methods", {})
    if options.check_trace and method_info.get("enabled") is True:
        max_score += _HTTP_METHOD_MAX
        score += _http_methods_score(method_info)

    sensitive_paths = get_section(result, "sensitive_paths", {})
    if options.check_sensitive_paths and sensitive_paths.get("enabled") is True:
        max_score += _SENSITIVE_PATHS_MAX
        score += _SENSITIVE_PATHS_MAX if not sensitive_paths.get("paths") else 0

    score = round(score / max_score * 100) if max_score else 0
    return score, _security_level(score)


def _security_level(score: int) -> str:
    """返回安全等级。"""
    if score >= 85:
        return "A级"
    if score >= 70:
        return "B级"
    return "C级"


def _tls_score(tls_info: Dict[str, Any]) -> int:
    """计算 TLS 配置得分。"""
    if not tls_info:
        return 0

    score = 0
    ssl_valid = tls_info.get("ssl_valid")

    if ssl_valid:
        score += 8

    days_left = tls_info.get("ssl_days_left")
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


def _http_methods_score(method_info: Dict[str, Any]) -> int:
    """按 TRACE 和其他方法暴露分别给分。"""
    score = 0
    if method_info.get("trace_enabled") is False:
        score += _HTTP_TRACE_MAX
    if method_info.get("trace_enabled") is False and not method_info.get("exposed_methods"):
        score += _HTTP_EXPOSED_METHODS_MAX
    return min(score, _HTTP_METHOD_MAX)


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

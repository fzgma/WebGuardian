"""安全评分规则。"""

from collections.abc import Mapping

from scanner.options import ScanOptions
from ui.result.models import JsonValue, SectionResult, SectionStatus

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


def calculate_score(
    checks: Mapping[str, SectionResult], options: ScanOptions
) -> tuple[int, str]:
    """按已启用的站点检查计算归一化评分。"""

    score = 0
    max_score = 0

    https = checks.get("https")
    if options.check_https and https is not None and https.enabled is True:
        max_score += _HTTPS_MAX
        if _value(https, "value") is True:
            score += _HTTPS_MAX

    tls = checks.get("tls")
    if options.check_ssl and tls is not None and tls.enabled is True:
        max_score += _TLS_MAX
        score += _tls_score(tls)

    dns_security = checks.get("dns_security")
    if (
        options.check_dns_security
        and dns_security is not None
        and dns_security.enabled is True
        and dns_security.status is not SectionStatus.SKIPPED
    ):
        max_score += _DNS_SECURITY_MAX
        score += _dns_security_score(dns_security)

    security_headers = checks.get("security_headers")
    if (
        options.check_security_headers
        and security_headers is not None
        and security_headers.enabled is True
    ):
        max_score += _SECURITY_HEADERS_MAX
        score += _int_value(security_headers, "score")

    if options.check_info_leak:
        info_leak = checks.get("info_leak")
        if info_leak is not None and info_leak.enabled is True:
            max_score += 10
        for field, weight in _INFO_LEAK_WEIGHTS.items():
            if info_leak is not None and _value(info_leak, field) is False:
                score += weight

    method_info = checks.get("http_methods")
    if options.check_trace and method_info is not None and method_info.enabled is True:
        max_score += _HTTP_METHOD_MAX
        score += _http_methods_score(method_info)

    sensitive_paths = checks.get("sensitive_paths")
    if (
        options.check_sensitive_paths
        and sensitive_paths is not None
        and sensitive_paths.enabled is True
    ):
        max_score += _SENSITIVE_PATHS_MAX
        if not _list_value(sensitive_paths, "paths"):
            score += _SENSITIVE_PATHS_MAX

    score = round(score / max_score * 100) if max_score else 0
    return score, _security_level(score)


def _security_level(score: int) -> str:
    """返回安全等级。"""

    if score >= 85:
        return "A级"
    if score >= 70:
        return "B级"
    return "C级"


def _tls_score(tls_info: SectionResult) -> int:
    """根据 TLS 证书、协议、套件和证书链计算分项得分。"""
    score = 0
    if _value(tls_info, "ssl_valid"):
        score += 8

    days_left = _value(tls_info, "ssl_days_left")
    if isinstance(days_left, int) and days_left > 7:
        score += 4

    supported_protocols = _list_value(tls_info, "supported_protocols")
    weak_protocols = _list_value(tls_info, "weak_protocols")
    if supported_protocols and not weak_protocols and all(
        proto in {"TLS 1.2", "TLS 1.3"} for proto in supported_protocols
    ):
        score += 4
    elif supported_protocols and not weak_protocols:
        score += 2

    if _value(tls_info, "cipher_weak") is False:
        score += 2
    if _value(tls_info, "chain_complete") is True or _value(
        tls_info, "chain_verified"
    ) is True:
        score += 2
    return min(score, _TLS_MAX)


def _http_methods_score(method_info: SectionResult) -> int:
    """根据 TRACE 和其他方法暴露情况计算分项得分。"""
    score = 0
    if _value(method_info, "trace_enabled") is False:
        score += _HTTP_TRACE_MAX
    if _value(method_info, "trace_enabled") is False and not _list_value(
        method_info, "exposed_methods"
    ):
        score += _HTTP_EXPOSED_METHODS_MAX
    return min(score, _HTTP_METHOD_MAX)


def _dns_security_score(dns_security: SectionResult) -> int:
    """根据 SPF、DMARC 和 CAA 配置计算分项得分。"""
    score = 0

    spf_policy = _object_value(dns_security, "spf").get("policy")
    if spf_policy == "strict":
        score += 5
    elif spf_policy == "softfail":
        score += 3

    dmarc_policy = _object_value(dns_security, "dmarc").get("policy")
    if dmarc_policy == "reject":
        score += 5
    elif dmarc_policy == "quarantine":
        score += 3

    caa = _object_value(dns_security, "caa")
    if caa.get("present") and caa.get("issuers"):
        score += 5
    elif caa.get("present"):
        score += 2
    return min(score, _DNS_SECURITY_MAX)


def _value(section: SectionResult, key: str) -> JsonValue:
    """读取 section 中指定键的动态检测值。"""
    return section.value(key)


def _int_value(section: SectionResult, key: str) -> int:
    """读取 section 中的整数值，类型不匹配时返回零。"""
    value = _value(section, key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _list_value(section: SectionResult, key: str) -> list[JsonValue]:
    """读取 section 中的列表值，类型不匹配时返回空列表。"""
    value = _value(section, key)
    return value if isinstance(value, list) else []


def _object_value(section: SectionResult, key: str) -> dict[str, JsonValue]:
    """读取 section 中的对象值，类型不匹配时返回空字典。"""
    value = _value(section, key)
    return value if isinstance(value, dict) else {}

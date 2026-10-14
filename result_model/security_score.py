"""安全评分规则。"""

from collections.abc import Mapping

from scanner.options import ScanOptions
from result_model.models import JsonValue, ScoreItem, ScoreReport, SectionResult, SectionStatus

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
) -> tuple[int | None, str]:
    """保留简洁入口；证据不足时不输出数值评分或正式评级。"""
    report = calculate_score_report(checks, options)
    return report.score, report.level


def calculate_score_report(
    checks: Mapping[str, SectionResult], options: ScanOptions
) -> ScoreReport:
    """将执行证据、检测范围和基础配置得分分开表达。"""
    specs = (
        ("https", "HTTPS", options.check_https, _HTTPS_MAX),
        ("tls", "TLS / SSL", options.check_ssl, _TLS_MAX),
        ("dns_security", "DNS 安全", options.check_dns_security, _DNS_SECURITY_MAX),
        ("security_headers", "安全响应头", options.check_security_headers, _SECURITY_HEADERS_MAX),
        ("info_leak", "暴露信息", options.check_info_leak, 10),
        ("http_methods", "HTTP 方法", options.check_trace, _HTTP_METHOD_MAX),
        ("sensitive_paths", "敏感路径", options.check_sensitive_paths, _SENSITIVE_PATHS_MAX),
    )
    items: list[ScoreItem] = []
    for name, label, enabled, maximum in specs:
        section = checks.get(name)
        if not enabled:
            items.append(ScoreItem(name, label, "disabled", None, maximum, "本次未启用。"))
            continue
        state, reason = _assessment(name, section)
        if state != "complete" or section is None:
            items.append(ScoreItem(name, label, state, None, maximum, reason))
            continue
        earned, explanation = _section_score(name, section)
        earned = max(0, min(earned, maximum))
        items.append(ScoreItem(
            name, label, "passed" if earned == maximum else "risk",
            earned, maximum, explanation,
        ))

    enabled_count = sum(item.status != "disabled" for item in items)
    evaluated_count = sum(item.status in {"passed", "risk"} for item in items)
    unknown_count = sum(item.status in {"unknown", "partial"} for item in items)
    not_applicable_count = sum(item.status == "not_applicable" for item in items)
    earned_points = sum(item.earned or 0 for item in items)
    possible_points = sum(
        item.maximum for item in items if item.status not in {"disabled", "not_applicable"}
    )
    if unknown_count:
        score = None
        level = "待完成"
        status = "partial" if evaluated_count or any(item.status == "partial" for item in items) else "unknown"
    elif not possible_points:
        score, level, status = None, "不适用", "not_applicable"
    else:
        score = round(earned_points / possible_points * 100)
        level, status = _security_level(score), "complete"
    return ScoreReport(
        score=score, level=level, status=status, enabled_count=enabled_count,
        evaluated_count=evaluated_count, unknown_count=unknown_count,
        not_applicable_count=not_applicable_count, earned_points=earned_points,
        possible_points=possible_points, items=items,
    )


def _assessment(name: str, section: SectionResult | None) -> tuple[str, str]:
    if section is None or section.enabled is not True:
        return "unknown", "已启用，但没有可用检测结果。"
    assessment = section.meta.get("assessment")
    if assessment == "not_applicable" or section.status is SectionStatus.SKIPPED:
        return "not_applicable", section.summary or "当前目标不适用。"
    if assessment in {"unknown", "partial"} or section.status is SectionStatus.ERROR:
        state = "partial" if assessment == "partial" else "unknown"
        return state, "；".join(section.warnings) or section.summary or "检测证据不足。"
    # 兼容旧模块，但绝不把异常后的空列表当作通过。
    if section.warnings and name in {"http_methods", "sensitive_paths", "dns_security"} and assessment != "complete":
        return "partial", "；".join(section.warnings)
    required: dict[str, bool] = {
        "https": isinstance(section.value("value"), bool),
        "tls": isinstance(section.value("ssl_valid"), bool) and (
            section.value("ssl_valid") is False or (
                isinstance(section.value("ssl_days_left"), int)
                and bool(_list_value(section, "supported_protocols"))
                and isinstance(section.value("cipher_weak"), bool)
                and (isinstance(section.value("chain_complete"), bool) or isinstance(section.value("chain_verified"), bool))
            )
        ),
        "dns_security": all(
            isinstance(_object_value(section, kind).get("present"), bool)
            or _object_value(section, kind).get("policy") is not None
            for kind in ("spf", "dmarc", "caa")
        ),
        "security_headers": isinstance(section.value("score"), int) and not isinstance(section.value("score"), bool),
        "info_leak": all(isinstance(section.value(key), bool) for key in _INFO_LEAK_WEIGHTS),
        "http_methods": isinstance(section.value("trace_enabled"), bool) and isinstance(section.value("exposed_methods"), list),
        "sensitive_paths": isinstance(section.value("paths"), list),
    }
    if not required.get(name, False):
        return "unknown", "缺少完成该分项评分所需的检测证据。"
    return "complete", ""


def _section_score(name: str, section: SectionResult) -> tuple[int, str]:
    if name == "https":
        return (10, "最终访问地址使用 HTTPS。") if section.value("value") else (0, "最终访问地址使用 HTTP。")
    if name == "tls":
        points = _tls_points(section)
        maximums = {"证书有效性": 8, "有效期": 4, "协议": 4, "套件": 2, "证书链": 2}
        return sum(points.values()), "；".join(f"{label} {value}/{maximums[label]} 分" for label, value in points.items()) + "。"
    if name == "dns_security":
        points = _dns_points(section)
        return sum(points.values()), "；".join(f"{label} {value}/5 分" for label, value in points.items()) + "。"
    if name == "security_headers":
        missing = _list_value(section, "missing")
        invalid = _list_value(section, "invalid")
        return _int_value(section, "score"), f"按安全头基础规则计分；缺失 {len(missing)} 项，配置问题 {len(invalid)} 项。"
    if name == "info_leak":
        labels = {"version_exposed": "版本信息", "framework_exposed": "框架信息", "meta_exposed": "meta 信息"}
        points = {key: weight if section.value(key) is False else 0 for key, weight in _INFO_LEAK_WEIGHTS.items()}
        return sum(points.values()), "；".join(f"{labels[key]} {value}/{_INFO_LEAK_WEIGHTS[key]} 分" for key, value in points.items()) + "。"
    if name == "http_methods":
        trace = "明确不可用，得 3 分" if section.value("trace_enabled") is False else "确认可用，得 0 分"
        methods = "、".join(str(item) for item in _list_value(section, "exposed_methods")) or "未声明其他高风险方法"
        return _http_methods_score(section), f"TRACE {trace}；{methods}。TRACE 不可用且无其他高风险声明时再得 2 分。"
    paths = _list_value(section, "paths")
    return (0, f"发现 {len(paths)} 个疑似暴露路径，需要人工确认。") if paths else (10, "已完成内置路径检查，未发现直接返回成功响应的疑似暴露路径。")


def _security_level(score: int) -> str:
    """返回安全等级。"""

    if score >= 85:
        return "A级"
    if score >= 70:
        return "B级"
    return "C级"


def _tls_points(tls_info: SectionResult) -> dict[str, int]:
    """根据 TLS 证书、协议、套件和证书链计算分项得分。"""
    points = {"证书有效性": 8 if _value(tls_info, "ssl_valid") is True else 0, "有效期": 0, "协议": 0, "套件": 0, "证书链": 0}
    days_left = _value(tls_info, "ssl_days_left")
    if isinstance(days_left, int) and days_left > 7:
        points["有效期"] = 4

    supported_protocols = _list_value(tls_info, "supported_protocols")
    weak_protocols = _list_value(tls_info, "weak_protocols")
    if supported_protocols and not weak_protocols and all(
        proto in {"TLS 1.2", "TLS 1.3"} for proto in supported_protocols
    ):
        points["协议"] = 4
    elif supported_protocols and not weak_protocols:
        points["协议"] = 2

    if _value(tls_info, "cipher_weak") is False:
        points["套件"] = 2
    if _value(tls_info, "chain_complete") is True or _value(
        tls_info, "chain_verified"
    ) is True:
        points["证书链"] = 2
    return points


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


def _dns_points(dns_security: SectionResult) -> dict[str, int]:
    """根据 SPF、DMARC 和 CAA 配置计算分项得分。"""
    points = {"SPF": 0, "DMARC": 0, "CAA": 0}

    spf_policy = _object_value(dns_security, "spf").get("policy")
    if spf_policy == "strict":
        points["SPF"] = 5
    elif spf_policy == "softfail":
        points["SPF"] = 3

    dmarc_policy = _object_value(dns_security, "dmarc").get("policy")
    if dmarc_policy == "reject":
        points["DMARC"] = 5
    elif dmarc_policy == "quarantine":
        points["DMARC"] = 3

    caa = _object_value(dns_security, "caa")
    if caa.get("present") and caa.get("issuers"):
        points["CAA"] = 5
    elif caa.get("present"):
        points["CAA"] = 2
    return points


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

"""响应头的有限语义检查，不替代完整的浏览器策略验证。"""

import re
from collections.abc import Mapping, Sequence
from typing import Any


SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
)
_NONCE_OR_HASH = re.compile(r"'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_-]+=*'", re.I)


def assess_security_headers(
    headers: Mapping[str, str],
    header_names: Sequence[str] = SECURITY_HEADERS,
) -> dict[str, Any]:
    """区分缺失、明显无效/过弱与通过有限检查的响应头。"""
    normalized = {name.lower(): value for name, value in headers.items()}
    missing: list[str] = []
    invalid: list[dict[str, str]] = []
    valid: list[str] = []
    for name in header_names:
        if name.lower() not in normalized:
            missing.append(name)
            continue
        value = normalized[name.lower()].strip()
        reasons = _header_reasons(name.lower(), value)
        if reasons:
            invalid.append({"header": name, "value": value, "reason": "；".join(reasons)})
        else:
            valid.append(name)
    coverage = len(valid) / len(header_names) if header_names else 0
    return {
        "score": round(coverage * 30),
        "missing": missing,
        "invalid": invalid,
        "valid": valid,
        "coverage": round(coverage * 100),
        "checked_count": len(header_names),
        "meta": {"assessment": "complete"},
    }


def _header_reasons(name: str, value: str) -> list[str]:
    if not value:
        return ["响应头值为空，未形成有效策略。"]
    if name == "strict-transport-security":
        # RFC 6797 §6.1.1：max-age 可以带引号；零值会删除 HSTS 策略。
        directives = [item.strip() for item in value.split(";") if item.strip()]
        ages = [item for item in directives if item.split("=", 1)[0].strip().lower() == "max-age"]
        if len(ages) != 1:
            return ["HSTS 必须包含且只能包含一个 max-age。"]
        match = re.fullmatch(r'max-age\s*=\s*(?:([0-9]+)|"([0-9]+)")', ages[0], re.I)
        if match is None:
            return ["HSTS max-age 必须是非负整数秒数。"]
        if not (match.group(1) or match.group(2)).lstrip("0"):
            return ["HSTS max-age=0 会撤销策略，不能提供持续的 HTTPS 约束。"]
    elif name == "x-frame-options" and value.upper() not in {"DENY", "SAMEORIGIN"}:
        return ["X-Frame-Options 应为 DENY 或 SAMEORIGIN；其他值不能作为有效的防嵌入策略。"]
    elif name == "x-content-type-options" and value.lower() != "nosniff":
        return ["X-Content-Type-Options 必须为 nosniff。"]
    elif name == "content-security-policy":
        return _csp_reasons(value)
    return []


def _csp_reasons(value: str) -> list[str]:
    """只报告各条同时生效的 CSP 都未约束的明确脚本风险。"""
    # CSP3 §2.2：重复指令取首次，逗号分隔的策略同时生效、共同收紧权限。
    policies: list[dict[str, list[str]]] = []
    for serialized in value.split(","):
        directives: dict[str, list[str]] = {}
        for part in serialized.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives.setdefault(tokens[0].lower(), tokens[1:])
        policies.append(directives)

    def sources(policy: dict[str, list[str]], kind: str) -> list[str] | None:
        if "sandbox" in policy and "allow-scripts" not in policy["sandbox"]:
            return []
        for directive in (kind, "script-src", "default-src"):
            if directive in policy:
                return policy[directive]
        return None

    element_lists = [sources(policy, "script-src-elem") for policy in policies]
    attribute_lists = [sources(policy, "script-src-attr") for policy in policies]
    eval_lists = [sources(policy, "script-src") for policy in policies]
    reasons: list[str] = []
    if all(items is None for items in element_lists):
        reasons.append("CSP 未设置 default-src、script-src 或 script-src-elem，未约束脚本来源。")
    else:
        for token, reason in (
            ("*", "CSP 脚本来源包含通配符 *，允许的脚本来源过宽。"),
            ("data:", "CSP 脚本来源允许 data:，可能执行内嵌数据脚本。"),
        ):
            if all(
                items is None or (token in items and "'strict-dynamic'" not in items)
                for items in element_lists
            ):
                reasons.append(reason)

    def allows_inline(items: list[str] | None) -> bool:
        if items is None:
            return True
        # CSP3 §6.7.3.2：nonce/hash/strict-dynamic 会使 unsafe-inline 失效。
        return (
            "'unsafe-inline'" in items
            and "'strict-dynamic'" not in items
            and not any(_NONCE_OR_HASH.fullmatch(item) for item in items)
        )

    if any(items is not None for items in element_lists) and all(map(allows_inline, element_lists)):
        reasons.append("CSP 允许任意内联脚本（unsafe-inline），且未被 nonce/hash 等约束。")
    if any(items is not None for items in attribute_lists) and all(map(allows_inline, attribute_lists)):
        reasons.append("CSP 允许任意内联事件处理器（unsafe-inline）。")
    if any(items is not None for items in eval_lists) and all(
        items is None or "'unsafe-eval'" in items for items in eval_lists
    ):
        reasons.append("CSP 允许 unsafe-eval，未限制字符串形式的脚本执行。")
    return reasons

"""DNS 安全检测。"""

import ipaddress
import re
from typing import Any, Dict, List

import dns.exception
import dns.resolver

from utils.control import check_stop
from utils.result_composer import wrap_section_result


DNS_RESOLVER_TIMEOUT = 1.0
DNS_RESOLVER_LIFETIME = 1.5


def run_dns_check(context: Any) -> dict[str, Any]:
    """执行 DNS 安全检测并返回标准 section。"""
    if not context.scan_options.check_dns_security:
        return wrap_section_result(
            "dns_security",
            _disabled_result(context.host),
            enabled=False,
            status="disabled",
            summary="DNS 安全检测已关闭。",
        )

    check_stop(context.stop_event)
    context.progress.update("正在检测 DNS 安全配置（SPF / DMARC / CAA）")
    dns_result = _detect_dns_security(
        context.host,
        stop_event=context.stop_event,
        progress=context.progress,
    )
    context.progress.update("DNS 安全检测完成", 1)
    return wrap_section_result(
        "dns_security",
        dns_result,
        enabled=True,
        status=dns_result.get("status", "ok"),
        summary="DNS 安全检测完成。",
        warnings=dns_result.get("warnings", []),
        findings=dns_result.get("findings", []),
    )


def _disabled_result(host: str = "") -> Dict[str, Any]:
    """返回关闭 DNS 检测时使用的 section 数据。"""
    return {
        "status": "missing",
        "domain": host,
        "lookup_domain": "",
        "spf": {"present": None, "records": [], "policy": None},
        "dmarc": {"present": None, "records": [], "policy": None},
        "caa": {"present": None, "records": [], "issuers": []},
        "findings": [],
        "warnings": [],
    }


def _detect_dns_security(host: str, stop_event=None, progress=None) -> Dict[str, Any]:
    """检测域名的 SPF、DMARC 和 CAA 配置。"""
    result: Dict[str, Any] = {
        "enabled": True,
        "status": "ok",
        "domain": host,
        "lookup_domain": "",
        "spf": {"present": None, "records": [], "policy": None},
        "dmarc": {"present": None, "records": [], "policy": None},
        "caa": {"present": None, "records": [], "issuers": []},
        "findings": [],
        "warnings": [],
    }

    if not host:
        result["status"] = "skipped"
        result["warnings"].append("DNS 安全检测已跳过：未获取到主机名。")
        return result

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        result["status"] = "skipped"
        result["warnings"].append("DNS 安全检测已跳过：当前输入是 IP 地址。")
        return result

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = DNS_RESOLVER_TIMEOUT
    resolver.lifetime = DNS_RESOLVER_LIFETIME

    lookup_candidates = _dns_lookup_candidates(host)
    lookup_domain = lookup_candidates[0]
    spf_records: List[str] = []
    dmarc_records: List[str] = []
    caa_records: Dict[str, Any] | None = None
    had_query_error = False

    for candidate in lookup_candidates:
        check_stop(stop_event)
        if progress is not None:
            progress.update(f"正在查询 SPF 记录：{candidate}")
        spf_records, spf_errors = _lookup_txt_records(resolver, candidate)
        if progress is not None:
            progress.update(f"正在查询 DMARC 记录：{candidate}")
        dmarc_records, dmarc_errors = _lookup_txt_records(
            resolver,
            f"_dmarc.{candidate}",
        )
        if progress is not None:
            progress.update(f"正在查询 CAA 记录：{candidate}")
        caa_records, caa_errors = _lookup_caa_records(resolver, candidate)
        result["warnings"].extend(spf_errors + dmarc_errors + caa_errors)

        if spf_errors or dmarc_errors or caa_errors:
            had_query_error = True

        has_records = bool(
            spf_records or dmarc_records or (caa_records and caa_records.get("records"))
        )
        if has_records:
            lookup_domain = candidate
            break

        if spf_errors or dmarc_errors or caa_errors:
            break

    result["lookup_domain"] = lookup_domain

    if had_query_error and not (
        spf_records or dmarc_records or (caa_records and caa_records.get("records"))
    ):
        result["status"] = "error"
        return result

    if spf_records:
        result["spf"]["present"] = True
        result["spf"]["records"] = spf_records
        spf_policy = _classify_spf(spf_records)
        result["spf"]["policy"] = spf_policy["policy"]
        result["findings"].extend(spf_policy["findings"])
    else:
        result["spf"]["present"] = False
        result["findings"].append(
            {
                "risk": "中",
                "type": "SPF 缺失",
                "message": f"未发现 {lookup_domain} 的 SPF 记录。",
                "suggestion": "为域名添加 SPF TXT 记录，限制可代表该域名发信的主机范围。",
            }
        )

    if dmarc_records:
        result["dmarc"]["present"] = True
        result["dmarc"]["records"] = dmarc_records
        dmarc_policy = _classify_dmarc(dmarc_records)
        result["dmarc"]["policy"] = dmarc_policy["policy"]
        result["findings"].extend(dmarc_policy["findings"])
    else:
        result["dmarc"]["present"] = False
        result["findings"].append(
            {
                "risk": "中",
                "type": "DMARC 缺失",
                "message": f"未发现 {lookup_domain} 的 DMARC 记录。",
                "suggestion": "为域名添加 _dmarc TXT 记录，并设置明确的 p 策略。",
            }
        )

    if caa_records and caa_records.get("records"):
        result["caa"]["present"] = True
        result["caa"]["records"] = caa_records.get("records", [])
        result["caa"]["issuers"] = caa_records.get("issuers", [])
        if not caa_records.get("has_issue"):
            result["findings"].append(
                {
                    "risk": "低",
                    "type": "CAA 限制较弱",
                    "message": f"{lookup_domain} 存在 CAA 记录，但未直接限制证书签发 CA。",
                    "suggestion": "如需收紧证书签发范围，可补充 issue 或 issuewild 约束。",
                }
            )
    else:
        result["caa"]["present"] = False
        result["findings"].append(
            {
                "risk": "低",
                "type": "CAA 缺失",
                "message": f"未发现 {lookup_domain} 的 CAA 记录。",
                "suggestion": "为域名添加 CAA 记录，限制允许签发证书的 CA。",
            }
        )

    if not result["findings"]:
        result["findings"].append(
            {
                "risk": "低",
                "type": "DNS 安全配置",
                "message": f"{lookup_domain} 的 SPF、DMARC 和 CAA 均未发现明显问题。",
                "suggestion": "保持当前 DNS 安全配置，并定期核对邮箱和证书策略。",
            }
        )

    return result


def _dns_lookup_candidates(host: str) -> List[str]:
    """生成 DNS 查询候选域名。"""
    normalized = (host or "").strip().rstrip(".").lower()
    candidates: List[str] = []
    if normalized:
        if normalized.startswith("www."):
            stripped = normalized[4:]
            if stripped and stripped not in candidates:
                candidates.append(stripped)
        candidates.append(normalized)
    return candidates


def _lookup_txt_records(
    resolver: dns.resolver.Resolver,
    name: str,
    *,
    stop_event=None,
) -> tuple[List[str], List[str]]:
    """查询 TXT 记录。"""
    check_stop(stop_event)
    try:
        answers = resolver.resolve(name, "TXT", search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], []
    except dns.exception.DNSException as exc:
        return [], [f"DNS 查询 TXT 失败：{name}，{exc}"]

    records: List[str] = []
    for answer in answers:
        text = _dns_record_text(answer)
        if text:
            records.append(text)
    return records, []


def _lookup_caa_records(
    resolver: dns.resolver.Resolver,
    name: str,
    *,
    stop_event=None,
) -> tuple[Dict[str, Any] | None, List[str]]:
    """查询 CAA 记录。"""
    check_stop(stop_event)
    try:
        answers = resolver.resolve(name, "CAA", search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None, []
    except dns.exception.DNSException as exc:
        return None, [f"DNS 查询 CAA 失败：{name}，{exc}"]

    records: List[str] = []
    issuers: List[str] = []
    has_issue = False
    for answer in answers:
        text = _dns_record_text(answer)
        if text:
            records.append(text)
        parsed = _parse_caa_text(text)
        if parsed is None:
            continue
        tag, value = parsed
        if tag in {"issue", "issuewild"}:
            has_issue = True
            if value:
                issuers.append(value)

    return {"records": records, "issuers": issuers, "has_issue": has_issue}, []


def _dns_record_text(record: Any) -> str:
    """把 DNS 记录转成可读文本。"""
    text = getattr(record, "to_text", None)
    if callable(text):
        return str(text()).strip().strip('"')

    strings = getattr(record, "strings", None)
    if strings:
        parts: list[str] = []
        for part in strings:
            if isinstance(part, bytes):
                parts.append(part.decode("utf-8", "ignore"))
            else:
                parts.append(str(part))
        return "".join(parts).strip()

    return str(record).strip()


def _parse_caa_text(text: str) -> tuple[str, str] | None:
    """解析 CAA 文本记录。"""
    candidate = (text or "").strip()
    if not candidate:
        return None

    parts = candidate.split(None, 2)
    if len(parts) < 2:
        return None

    tag = parts[1].lower()
    value = parts[2].strip().strip('"') if len(parts) > 2 else ""
    return tag, value


def _classify_spf(records: List[str]) -> Dict[str, Any]:
    """分析 SPF 记录的收紧程度。"""
    findings: List[Dict[str, Any]] = []
    record = next((item for item in records if "v=spf1" in item.lower()), "")
    policy = "unknown"

    if not record:
        findings.append(
            {
                "risk": "中",
                "type": "SPF 记录无效",
                "message": "TXT 记录中未发现有效的 SPF 策略。",
                "suggestion": "确认 SPF 记录是否正确发布，且内容以 v=spf1 开头。",
            }
        )
        return {"policy": policy, "findings": findings}

    tokens = record.split()
    all_token = next(
        (token.lower() for token in tokens if token.lower().endswith("all")),
        "",
    )
    if all_token in {"+all", "all"}:
        policy = "open"
        findings.append(
            {
                "risk": "高",
                "type": "SPF 过宽",
                "message": f"SPF 记录允许几乎任意主机代表域名发信：{record}",
                "suggestion": "将 SPF 收紧为明确的发送主机，并使用 -all 结束策略。",
            }
        )
    elif all_token == "~all":
        policy = "softfail"
        findings.append(
            {
                "risk": "低",
                "type": "SPF 策略偏宽",
                "message": f"SPF 记录使用软失败策略：{record}",
                "suggestion": "如条件允许，可进一步收紧为 -all。",
            }
        )
    elif all_token == "-all":
        policy = "strict"
    else:
        findings.append(
            {
                "risk": "中",
                "type": "SPF 结束策略不明确",
                "message": f"SPF 记录未看到明确的 -all 结束策略：{record}",
                "suggestion": "建议使用 -all 收尾，明确拒绝未授权的发信来源。",
            }
        )

    return {"policy": policy, "findings": findings}


def _classify_dmarc(records: List[str]) -> Dict[str, Any]:
    """分析 DMARC 策略。"""
    findings: List[Dict[str, Any]] = []
    record = next((item for item in records if "v=dmarc1" in item.lower()), "")
    policy = "unknown"

    if not record:
        findings.append(
            {
                "risk": "中",
                "type": "DMARC 记录无效",
                "message": "TXT 记录中未发现有效的 DMARC 策略。",
                "suggestion": "确认 _dmarc 子域已正确发布 DMARC 记录。",
            }
        )
        return {"policy": policy, "findings": findings}

    match = re.search(r"(?i)(?:^|;)\s*p\s*=\s*([a-z]+)", record)
    dmarc_policy = match.group(1).lower() if match else ""
    if dmarc_policy == "reject":
        policy = "reject"
    elif dmarc_policy == "quarantine":
        policy = "quarantine"
        findings.append(
            {
                "risk": "低",
                "type": "DMARC 仍偏宽",
                "message": f"DMARC 策略为 quarantine：{record}",
                "suggestion": "如条件允许，可进一步收紧为 p=reject。",
            }
        )
    elif dmarc_policy == "none":
        policy = "none"
        findings.append(
            {
                "risk": "中",
                "type": "DMARC 仅监控",
                "message": f"DMARC 策略为 none：{record}",
                "suggestion": "建议尽快提升为 quarantine 或 reject，以降低仿冒邮件风险。",
            }
        )
    else:
        findings.append(
            {
                "risk": "中",
                "type": "DMARC 策略不明确",
                "message": f"DMARC 记录中未看到明确的 p 策略：{record}",
                "suggestion": "为 DMARC 增加明确的 p=reject 或 p=quarantine。",
            }
        )

    return {"policy": policy, "findings": findings}

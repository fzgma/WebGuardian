"""扫描错误归类与提示。"""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ScanErrorInfo:
    """扫描错误的友好展示信息。"""

    summary: str
    hint: str
    detail: str
    kind: str = "scan"


_DNS_PATTERNS = (
    "nameresolutionerror",
    "failed to resolve",
    "getaddrinfo failed",
    "temporary failure in name resolution",
    "name or service not known",
)
_TIMEOUT_PATTERNS = (
    "readtimeout",
    "connecttimeout",
    "timeout",
    "timed out",
)
_CONNECT_PATTERNS = (
    "connection refused",
    "failed to establish a new connection",
    "newconnectionerror",
    "connection aborted",
    "connection reset",
)
_SSL_PATTERNS = (
    "ssLError",
    "certificate verify failed",
    "tls",
    "ssl",
    "certificate",
)
_PROXY_PATTERNS = (
    "proxyerror",
    "tunnel connection failed",
)


def explain_scan_error(raw_error: str) -> ScanErrorInfo:
    """把原始错误转换成更适合界面展示的提示。"""
    text = (raw_error or "").strip()
    lowered = text.lower()

    if _has_any(lowered, _DNS_PATTERNS):
        return ScanErrorInfo(
            summary="DNS 解析失败",
            hint="请检查网址拼写是否正确，确认域名是否存在，并检查本机或网络环境的 DNS 设置。",
            detail=text,
        )

    if _has_any(lowered, _TIMEOUT_PATTERNS):
        return ScanErrorInfo(
            summary="请求超时",
            hint="目标站点响应过慢或网络不稳定。可以稍后重试，或检查代理、链路质量和目标服务状态。",
            detail=text,
        )

    if _has_any(lowered, _CONNECT_PATTERNS):
        return ScanErrorInfo(
            summary="连接失败",
            hint="请检查目标端口是否开放，域名，IP是否正确；确认网络环境是否允许访问该站点，或检查代理设置。",
            detail=text,
        )

    if _has_any(lowered, _PROXY_PATTERNS):
        return ScanErrorInfo(
            summary="代理连接失败",
            hint="当前网络代理可能不可用，或代理配置与目标站点不兼容。请检查代理设置后重试。",
            detail=text,
        )

    if _has_any(lowered, _SSL_PATTERNS):
        return ScanErrorInfo(
            summary="TLS / SSL 握手失败",
            hint="可能是证书链不完整、证书已过期、SNI 不匹配，或被中间代理拦截。请检查证书和网络环境。",
            detail=text,
        )

    status_match = re.search(r"异常状态码：(\d{3})", text)
    if status_match:
        status_code = int(status_match.group(1))
        if status_code in {401, 403}:
            return ScanErrorInfo(
                summary=f"访问被拒绝（HTTP {status_code}）",
                hint="目标站点可能需要登录、存在访问控制，或被 WAF / 安全策略拦截。",
                detail=text,
            )
        if 400 <= status_code < 500:
            return ScanErrorInfo(
                summary=f"HTTP 客户端错误（{status_code}）",
                hint="目标站点返回了客户端错误。请检查 URL、路径或访问权限。",
                detail=text,
            )
        if 500 <= status_code < 600:
            return ScanErrorInfo(
                summary=f"HTTP 服务端错误（{status_code}）",
                hint="目标站点服务端可能暂时不可用。可以稍后重试，或联系站点管理员确认状态。",
                detail=text,
            )

    if _looks_like_url_validation_message(lowered):
        return ScanErrorInfo(
            summary=text,
            hint="",
            detail=text,
            kind="validation",
        )

    return ScanErrorInfo(
        summary="检测失败",
        hint="请稍后重试；如果问题持续存在，可以查看详细错误信息排查网络、证书或目标站点状态。",
        detail=text,
    )


def _has_any(value: str, patterns: tuple[str, ...]) -> bool:
    """判断文本是否命中任一关键字。"""
    return any(pattern in value for pattern in patterns)


def _looks_like_url_validation_message(value: str) -> bool:
    """判断是否是别处已经明确返回的 URL 校验信息。"""
    return any(
        keyword in value
        for keyword in (
            "url 不能为空",
            "url 格式不正确",
            "主机名不正确",
            "端口号不正确",
            "不支持用户名或密码",
            "仅支持 http 和 https 协议",
        )
    )

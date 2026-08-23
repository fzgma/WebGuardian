"""TLS/SSL 证书与配置检测。"""

import re
import socket
import ssl
from datetime import datetime, timezone
from collections.abc import Callable, Sequence
from typing import Any, Dict, List, cast
from urllib.parse import urlparse

from cryptography import x509

from utils.control import check_stop
from ui.result.composer import wrap_section_result
from ui.result.models import ScanContext, SectionResult, SectionStatus

_TLS_VERSION_SPECS: list[tuple[str, ssl.TLSVersion, str]] = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1, "弱"),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1, "弱"),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2, "现代"),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3, "现代"),
]
_WEAK_CIPHER_RE = re.compile(r"(?i)\b(?:NULL|EXPORT|RC4|3DES|DES|MD5|IDEA|SEED)\b")


def run_tls_check(context: ScanContext, response: Any) -> SectionResult:
    """执行 TLS 检测并返回标准 section。"""
    options = context.scan_options
    if not options.check_ssl:
        return wrap_section_result(
            "tls",
            _disabled_result(),
            enabled=False,
            status=SectionStatus.DISABLED,
            summary="SSL 检测已关闭。",
        )

    check_stop(context.stop_event)
    tls_result = inspect_tls_configuration(response.url)
    context.progress.update("正在检测 SSL 证书", 1)
    return wrap_section_result(
        "tls",
        tls_result,
        enabled=True,
        status=SectionStatus.OK if tls_result.get("ok") else SectionStatus.ERROR,
        summary="TLS / SSL 检测完成。",
        warnings=tls_result.get("warnings", []),
    )


def inspect_tls_configuration(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """检查 TLS 证书、协议、套件和链信息。"""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return _empty_result()

    host = parsed.hostname
    port = parsed.port or 443
    result = _empty_result(host, port)

    protocol_probes = _probe_tls_versions(host, port, timeout=timeout)
    result["supported_protocols"] = [
        item["label"] for item in protocol_probes if item["supported"]
    ]
    result["weak_protocols"] = [
        item["label"]
        for item in protocol_probes
        if item["supported"] and item["risk"] == "弱"
    ]
    result["protocol_probes"] = protocol_probes

    try:
        handshake = _perform_verified_handshake(host, port, timeout=timeout)
    except Exception as exc:
        result["ok"] = False
        result["ssl_valid"] = False
        result["warnings"].append(f"TLS 握手失败：{exc}")
        return result

    cert = handshake["certificate"]
    negotiated = handshake["negotiated"]
    expiry = _certificate_expiry(cert)
    days_left = (expiry - datetime.now(timezone.utc)).days if expiry is not None else -1
    cipher_name = negotiated.get("cipher_name", "")
    cipher_bits = negotiated.get("cipher_bits", 0)
    protocol = negotiated.get("protocol", "")

    result["ok"] = True
    result["ssl_valid"] = True
    result["ssl_days_left"] = days_left
    result["protocol"] = protocol
    result["cipher"] = negotiated
    result["cipher_weak"] = _is_weak_cipher(cipher_name, cipher_bits)
    result["chain_verified"] = handshake.get("chain_verified")
    result["chain_length"] = handshake.get("chain_length")
    result["chain_complete"] = handshake.get("chain_complete")
    result["certificate"] = {
        "subject": _name_to_text(cert.subject),
        "issuer": _name_to_text(cert.issuer),
        "not_before": _format_dt(
            cert.not_valid_before_utc
            if hasattr(cert, "not_valid_before_utc")
            else cert.not_valid_before
        ),
        "not_after": _format_dt(expiry),
        "serial_number": format(cert.serial_number, "x"),
    }
    result["supported_protocols_label"] = (
        "，".join(result["supported_protocols"])
        if result["supported_protocols"]
        else ""
    )

    if result["weak_protocols"]:
        result["warnings"].append(
            f"检测到弱 TLS 协议支持：{', '.join(result['weak_protocols'])}"
        )
    if result["cipher_weak"]:
        result["warnings"].append(f"检测到弱加密套件：{cipher_name}")
    if result["chain_complete"] is False:
        result["warnings"].append("证书链信息不完整或仅返回了单张证书。")

    return result


def _disabled_result() -> Dict[str, Any]:
    """返回关闭 TLS 检测时使用的 section 数据。"""
    return {
        "ok": False,
        "ssl_valid": None,
        "ssl_days_left": None,
        "host": "",
        "port": 443,
        "protocol": "",
        "cipher": {},
        "cipher_weak": None,
        "supported_protocols": [],
        "supported_protocols_label": "",
        "weak_protocols": [],
        "protocol_probes": [],
        "chain_verified": None,
        "chain_length": None,
        "chain_complete": None,
        "certificate": {},
        "warnings": [],
    }


def _empty_result(host: str = "", port: int = 443) -> Dict[str, Any]:
    """返回空的 TLS 结果结构。"""
    return {
        "ok": False,
        "ssl_valid": False,
        "ssl_days_left": -1,
        "host": host,
        "port": port,
        "protocol": "",
        "cipher": {},
        "cipher_weak": False,
        "supported_protocols": [],
        "supported_protocols_label": "",
        "weak_protocols": [],
        "protocol_probes": [],
        "chain_verified": None,
        "chain_length": None,
        "chain_complete": None,
        "certificate": {},
        "warnings": [],
    }


def _certificate_expiry(cert: x509.Certificate) -> datetime | None:
    """提取证书到期时间。"""
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc

    expiry = cert.not_valid_after
    if expiry.tzinfo is None:
        return expiry.replace(tzinfo=timezone.utc)
    return expiry.astimezone(timezone.utc)


def _format_dt(value: datetime | None) -> str:
    """格式化时间。"""
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _name_to_text(name: x509.Name) -> str:
    """把证书主体或颁发者转成可读文本。"""
    parts: List[str] = []
    for attr in name:
        value = attr.value.strip()
        if value:
            parts.append(f"{attr.oid._name or attr.oid.dotted_string}={value}")
    return ", ".join(parts)


def _make_context(*, verify: bool, version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    """创建 TLS 上下文。"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = (
        ssl.TLSVersion.MINIMUM_SUPPORTED if version is None else version
    )
    context.maximum_version = (
        ssl.TLSVersion.MAXIMUM_SUPPORTED if version is None else version
    )
    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _probe_tls_versions(host: str, port: int, *, timeout: float) -> list[Dict[str, Any]]:
    """探测服务器支持的 TLS 版本。"""
    probes: list[Dict[str, Any]] = []
    for label, version, risk in _TLS_VERSION_SPECS:
        supported = False
        error = ""
        try:
            context = _make_context(verify=False, version=version)
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    negotiated = tls_sock.version() or label
                    if negotiated:
                        supported = True
        except Exception as exc:
            error = str(exc)
        probes.append(
            {
                "label": label,
                "supported": supported,
                "risk": risk if supported else "",
                "error": error,
            }
        )
    return probes


def _perform_verified_handshake(host: str, port: int, *, timeout: float) -> Dict[str, Any]:
    """执行一次带证书验证的 TLS 握手。"""
    context = _make_context(verify=True)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            if not der_cert:
                raise ValueError("未获取到服务器证书")

            cert = x509.load_der_x509_certificate(der_cert)
            cipher_name, tls_version, cipher_bits = tls_sock.cipher() or ("", "", 0)
            chain_verified = True
            chain_length = None
            chain_complete = None
            get_verified_chain = getattr(tls_sock, "get_verified_chain", None)
            get_unverified_chain = getattr(tls_sock, "get_unverified_chain", None)
            if callable(get_verified_chain):
                try:
                    verified_chain = cast(
                        Callable[[], Sequence[object]], get_verified_chain
                    )()
                    chain_length = (
                        len(verified_chain) if verified_chain is not None else None
                    )
                    chain_complete = chain_length is not None and chain_length >= 2
                except Exception:
                    chain_verified = True
            elif callable(get_unverified_chain):
                try:
                    unverified_chain = cast(
                        Callable[[], Sequence[object]], get_unverified_chain
                    )()
                    chain_length = (
                        len(unverified_chain) if unverified_chain is not None else None
                    )
                    chain_complete = chain_length is not None and chain_length >= 2
                except Exception:
                    chain_verified = True

            return {
                "certificate": cert,
                "negotiated": {
                    "protocol": tls_sock.version() or tls_version or "",
                    "cipher_name": cipher_name or "",
                    "cipher_bits": int(cipher_bits or 0),
                },
                "chain_verified": chain_verified,
                "chain_length": chain_length,
                "chain_complete": chain_complete,
            }


def _is_weak_cipher(name: str, bits: int) -> bool:
    """判断套件是否明显偏弱。"""
    if bits and bits < 128:
        return True
    return bool(_WEAK_CIPHER_RE.search(name or ""))

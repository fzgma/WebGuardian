"""TLS/SSL 证书检测。"""
from datetime import datetime, timezone
import socket
import ssl
from typing import Tuple
from urllib.parse import urlparse

from cryptography import x509


def _certificate_expiry(cert: x509.Certificate) -> datetime | None:
    """提取证书到期时间。"""
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc

    expiry = cert.not_valid_after
    if expiry.tzinfo is None:
        return expiry.replace(tzinfo=timezone.utc)
    return expiry.astimezone(timezone.utc)


def check_ssl_certificate(url: str, timeout: float = 5.0) -> Tuple[bool, int]:
    """通过独立 TLS 握手检查证书有效性和剩余天数。"""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False, -1

    port = parsed.port or 443
    context = ssl.create_default_context()

    try:
        with socket.create_connection((parsed.hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                if not der_cert:
                    return True, -1

                cert = x509.load_der_x509_certificate(der_cert)
                expiry = _certificate_expiry(cert)
                if expiry is None:
                    return True, -1

                days_left = (expiry - datetime.now(timezone.utc)).days
                return True, days_left
    except Exception:
        return False, -1

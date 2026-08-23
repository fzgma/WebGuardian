"""网站可用性指标采集。"""

import socket
import ssl
import sys
import threading
import warnings
from datetime import datetime
from typing import Any, Callable, cast

import requests
import urllib3.connection as urllib3_connection
from requests.adapters import HTTPAdapter
from urllib3 import poolmanager
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import (
    LocationParseError,
    NameResolutionError,
    NewConnectionError,
    SystemTimeWarning
)
from urllib3.util.connection import _set_socket_options, allowed_gai_family
from urllib3.util.timeout import _DEFAULT_TIMEOUT

from utils.timer import Timer


class AvailabilityTimingMixin:
    """给 urllib3 连接对象挂载可用性计时。"""

    _availability_timings: dict[str, float]

    def _availability_bucket(self: Any) -> dict[str, float]:
        """获取或初始化当前连接的可用性计时容器。"""
        bucket = getattr(self, "_availability_timings", None)
        if isinstance(bucket, dict):
            return cast(dict[str, float], bucket)
        bucket = cast(dict[str, float], {})
        self._availability_timings = bucket
        return bucket

    def _new_conn(self: Any) -> socket.socket:
        """建立 socket 连接并记录 DNS / TCP 耗时。"""
        try:
            host: str = self._dns_host
            if host.startswith("["):
                host = host.strip("[]")

            try:
                host.encode("idna")
            except UnicodeError:
                raise LocationParseError(f"'{host}', label empty or too long") from None

            family = allowed_gai_family()
            dns_timer = Timer()
            addresses = socket.getaddrinfo(host, self.port, family, socket.SOCK_STREAM)
            dns_seconds = dns_timer.elapsed_seconds()

            err: OSError | None = None
            tcp_seconds = 0.0
            for res in addresses:
                af, socktype, proto, _canonname, sa = res
                sock: socket.socket | None = None
                attempt_timer = Timer()
                try:
                    sock = socket.socket(af, socktype, proto)
                    _set_socket_options(sock, self.socket_options)

                    if self.timeout is not _DEFAULT_TIMEOUT:
                        sock.settimeout(cast(float | None, self.timeout))
                    if self.source_address:
                        sock.bind(self.source_address)

                    sock.connect(sa)
                    tcp_seconds += attempt_timer.elapsed_seconds()
                    err = None
                    self._availability_bucket().update(
                        {
                            "dns_seconds": dns_seconds,
                            "tcp_connect_seconds": tcp_seconds,
                        }
                    )
                    sys.audit("http.client.connect", self, self.host, self.port)
                    return sock
                except OSError as exc:
                    tcp_seconds += attempt_timer.elapsed_seconds()
                    err = exc
                    if sock is not None:
                        sock.close()

            if err is not None:
                try:
                    raise err
                finally:
                    err = None
            raise OSError("getaddrinfo returns an empty list")

        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc
        except socket.timeout as exc:
            raise NewConnectionError(
                self,
                f"Failed to establish a new connection: {exc}",
            ) from exc
        except OSError as exc:
            raise NewConnectionError(
                self,
                f"Failed to establish a new connection: {exc}",
            ) from exc


class AvailabilityHTTPConnection(AvailabilityTimingMixin, HTTPConnection):
    """带可用性计时的 HTTP 连接。"""


class AvailabilityHTTPSConnection(AvailabilityTimingMixin, HTTPSConnection):
    """带可用性计时的 HTTPS 连接。"""

    def connect(self: Any) -> None:
        """建立 HTTPS 连接并记录 TLS 握手耗时。"""
        sock_and_verified: Any = None
        http2_probe = getattr(urllib3_connection, "http2_probe", None)
        alpn_protocols = getattr(ssl, "ALPN_PROTOCOLS", ())

        if self._tunnel_host is not None and self._tunnel_port is not None:
            probe_http2_host: str = cast(str, self._tunnel_host)
            probe_http2_port: int = cast(int, self._tunnel_port)
        else:
            probe_http2_host = cast(str, self.host)
            probe_http2_port = cast(int, self.port)

        if http2_probe is not None and "h2" in alpn_protocols:
            target_supports_http2 = http2_probe.acquire_and_get(
                host=probe_http2_host, port=probe_http2_port
            )
        else:
            target_supports_http2 = False

        if self._connect_callback is not None:
            self._connect_callback(
                "before connect",
                thread_id=threading.get_ident(),
                target_supports_http2=target_supports_http2,
            )

        try:
            sock: socket.socket | ssl.SSLSocket
            self.sock = sock = self._new_conn()
            server_hostname: str = self.host
            tls_in_tls = False

            if self.proxy_is_tunneling:
                if self._tunnel_scheme == "https":
                    self.sock = sock = self._connect_tls_proxy(self.host, sock)
                    tls_in_tls = True
                elif self._tunnel_scheme == "http":
                    self.proxy_is_verified = False

                self._has_connected_to_proxy = True
                self._tunnel()
                server_hostname = cast(str, self._tunnel_host)

            if self.server_hostname is not None:
                server_hostname = cast(str, self.server_hostname)

            is_time_off = datetime.today().date() < urllib3_connection.RECENT_DATE
            if is_time_off:
                warnings.warn(
                    (
                        f"System time is way off (before {urllib3_connection.RECENT_DATE}). "
                        "This will probably lead to SSL verification errors"
                    ),
                    SystemTimeWarning,
                )

            server_hostname_rm_dot = server_hostname.rstrip(".")
            handshake_timer = Timer()
            ssl_wrap = cast(
                Callable[..., Any],
                getattr(urllib3_connection, "_ssl_wrap_socket_and_match_hostname"),
            )
            sock_and_verified = ssl_wrap(
                sock=sock,
                cert_reqs=self.cert_reqs,
                ssl_version=self.ssl_version,
                ssl_minimum_version=self.ssl_minimum_version,
                ssl_maximum_version=self.ssl_maximum_version,
                ca_certs=self.ca_certs,
                ca_cert_dir=self.ca_cert_dir,
                ca_cert_data=self.ca_cert_data,
                cert_file=self.cert_file,
                key_file=self.key_file,
                key_password=self.key_password,
                server_hostname=server_hostname_rm_dot,
                ssl_context=self.ssl_context,
                tls_in_tls=tls_in_tls,
                assert_hostname=self.assert_hostname,
                assert_fingerprint=self.assert_fingerprint,
            )
            self.sock = sock_and_verified.socket
            self._availability_bucket()["tls_handshake_seconds"] = handshake_timer.elapsed_seconds()

        except BaseException:
            if self._connect_callback is not None:
                self._connect_callback(
                    "after connect failure",
                    thread_id=threading.get_ident(),
                    target_supports_http2=target_supports_http2,
                )

            if http2_probe is not None and target_supports_http2 is None:
                http2_probe.set_and_release(
                    host=probe_http2_host, port=probe_http2_port, supports_http2=None
                )
            raise

        if http2_probe is not None and target_supports_http2 is None:
            selected_alpn_protocol = cast(
                Callable[[], str | None],
                getattr(sock_and_verified.socket, "selected_alpn_protocol"),
            )
            supports_http2 = selected_alpn_protocol() == "h2"
            http2_probe.set_and_release(
                host=probe_http2_host,
                port=probe_http2_port,
                supports_http2=supports_http2,
            )

        if self.proxy_is_forwarding:
            self.is_verified = False
        else:
            self.is_verified = bool(sock_and_verified.is_verified)

        self._has_connected_to_proxy = bool(self.proxy)
        if self._has_connected_to_proxy and self.proxy_is_verified is None:
            self.proxy_is_verified = bool(sock_and_verified.is_verified)


class AvailabilityHTTPConnectionPool(HTTPConnectionPool):
    """HTTP 连接池。"""

    ConnectionCls: type[HTTPConnection] = AvailabilityHTTPConnection  #type: ignore


class AvailabilityHTTPSConnectionPool(HTTPSConnectionPool):
    """HTTPS 连接池。"""

    ConnectionCls: type[HTTPSConnection] = AvailabilityHTTPSConnection #type: ignore


class AvailabilityPoolManager(poolmanager.PoolManager):
    """使用可用性连接类的 PoolManager。"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """初始化支持可用性计时的连接池管理器。"""
        super().__init__(*args, **kwargs)
        setattr(self, "pool_classes_by_scheme", {
            "http": AvailabilityHTTPConnectionPool,
            "https": AvailabilityHTTPSConnectionPool,
        })


class AvailabilityAdapter(HTTPAdapter):
    """给 requests session 注入可用性连接类。"""

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: Any,
    ) -> None:
        """创建使用可用性连接池的 PoolManager。"""
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = AvailabilityPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        """创建代理连接池并注入可用性连接类型。"""
        manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        if hasattr(manager, "pool_classes_by_scheme"):
            setattr(manager, "pool_classes_by_scheme", {
                "http": AvailabilityHTTPConnectionPool,
                "https": AvailabilityHTTPSConnectionPool,
            })
        return manager


def build_availability_result(
    response: requests.Response,
    *,
    total_seconds: float,
    timings: dict[str, float] | None = None,
) -> dict[str, float | int | bool | None]:
    """把响应对象转换为可用性展示数据。"""
    if timings is None:
        raw = getattr(response, "raw", None)
        connection = getattr(raw, "_connection", None)
        timings = getattr(connection, "_availability_timings", {}) if connection else {}
    if not isinstance(timings, dict):
        timings = {}

    request_bytes = _estimate_request_bytes(getattr(response, "request", None))
    response_bytes = _estimate_response_bytes(response)
    total_bytes = None
    if request_bytes is not None and response_bytes is not None:
        total_bytes = request_bytes + response_bytes

    ttfb_seconds = _seconds_from_timedelta(getattr(response, "elapsed", None))

    return {
        "enabled": True,
        "dns_seconds": timings.get("dns_seconds"),
        "tcp_connect_seconds": timings.get("tcp_connect_seconds"),
        "tls_handshake_seconds": timings.get("tls_handshake_seconds"),
        "ttfb_seconds": ttfb_seconds,
        "total_seconds": total_seconds,
        "request_bytes": request_bytes,
        "response_bytes": response_bytes,
        "total_bytes": total_bytes,
    }


def _seconds_from_timedelta(value: Any) -> float | None:
    """把 timedelta 转成秒。"""
    if value is None:
        return None
    seconds = getattr(value, "total_seconds", None)
    if callable(seconds):
        try:
            result = seconds()
        except (TypeError, ValueError):
            return None

        if isinstance(result, (int, float)):
            numeric_result = float(result)
            return numeric_result if numeric_result >= 0 else None

        return None
    return None


def _estimate_request_bytes(request: Any) -> int | None:
    """估算请求发送量。"""
    if request is None:
        return None

    method = getattr(request, "method", "") or "GET"
    path = getattr(request, "path_url", "") or "/"
    start_line = f"{method} {path} HTTP/1.1\r\n"

    headers = getattr(request, "headers", {}) or {}
    header_text = "".join(f"{key}: {value}\r\n" for key, value in headers.items())

    body_bytes = _body_length(getattr(request, "body", None))
    return len(start_line.encode("utf-8")) + len(header_text.encode("utf-8")) + 2 + body_bytes


def _estimate_response_bytes(response: requests.Response) -> int | None:
    """估算响应接收量。"""
    raw = getattr(response, "raw", None)
    if raw is not None:
        fp_bytes = getattr(raw, "_fp_bytes_read", None)
        if isinstance(fp_bytes, int) and fp_bytes >= 0:
            return fp_bytes

    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return len(content)

    return None


def _body_length(body: Any) -> int:
    """估算请求体长度。"""
    if body is None:
        return 0
    if isinstance(body, bytes):
        return len(body)
    if isinstance(body, bytearray):
        return len(body)
    if isinstance(body, str):
        return len(body.encode("utf-8"))
    if hasattr(body, "read"):
        return 0
    try:
        return len(body)
    except Exception:
        return 0

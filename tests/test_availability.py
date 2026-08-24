"""网站可用性指标结果测试。"""

from datetime import timedelta
from types import SimpleNamespace
from typing import cast

import requests

from scanner.basescan.availability import build_availability_result


def test_build_availability_result_preserves_all_timing_and_byte_metrics() -> None:
    """可用性结果应包含 DNS、TCP、TLS、TTFB 与请求/响应流量。"""
    request = SimpleNamespace(
        method="POST",
        path_url="/scan",
        headers={"Host": "example.com"},
        body="{}",
    )
    response = cast(
        requests.Response,
        SimpleNamespace(
            request=request,
            raw=SimpleNamespace(_fp_bytes_read=240),
            elapsed=timedelta(milliseconds=125),
            content=b"ignored because raw byte count is available",
        ),
    )

    result = build_availability_result(
        response,
        total_seconds=0.8,
        timings={
            "dns_seconds": 0.01,
            "tcp_connect_seconds": 0.02,
            "tls_handshake_seconds": 0.03,
        },
    )

    assert result["dns_seconds"] == 0.01
    assert result["tcp_connect_seconds"] == 0.02
    assert result["tls_handshake_seconds"] == 0.03
    assert result["ttfb_seconds"] == 0.125
    assert result["total_seconds"] == 0.8
    assert result["request_bytes"] == 44
    assert result["response_bytes"] == 240
    assert result["total_bytes"] == 284


def test_build_availability_result_handles_missing_optional_metrics() -> None:
    """未能采集的连接指标应保持空值而不是伪造数据。"""
    response = cast(
        requests.Response,
        SimpleNamespace(request=None, raw=None, elapsed=timedelta(seconds=-1), content=None),
    )

    result = build_availability_result(response, total_seconds=0.1, timings={})

    assert result["dns_seconds"] is None
    assert result["tcp_connect_seconds"] is None
    assert result["tls_handshake_seconds"] is None
    assert result["ttfb_seconds"] is None
    assert result["total_bytes"] is None

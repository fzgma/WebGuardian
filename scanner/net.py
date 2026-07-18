from __future__ import annotations

from typing import Tuple
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 5
DEFAULT_HEADERS = {
    "User-Agent": "WebGuardian/1.0 (+Security Scanner)"
}


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    return session


def http_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs,
) -> requests.Response:
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    allow_redirects = kwargs.pop("allow_redirects", True)
    return session.request(
        method=method,
        url=url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        **kwargs,
    )


def validate_input_url(raw_url: str) -> Tuple[bool, str]:
    if not raw_url or not raw_url.strip():
        return False, "URL 不能为空"

    candidate = raw_url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    if not parsed.netloc:
        return False, "URL 格式不正确，请输入类似 example.com 或 https://example.com"

    return True, ""


def normalize_url(raw_url: str, session: requests.Session) -> str:
    raw_url = raw_url.strip()

    if raw_url.startswith(("http://", "https://")):
        return raw_url

    https_url = "https://" + raw_url
    http_url = "http://" + raw_url

    try:
        http_request(session, "GET", https_url)
        return https_url
    except Exception:
        return http_url

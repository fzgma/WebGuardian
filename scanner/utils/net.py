import ipaddress
import string
from typing import Tuple
from urllib.parse import urlparse
import unicodedata

import requests


DEFAULT_TIMEOUT = 5
# 尽量模拟普通浏览器的导航请求头，降低被简单爬虫规则拦截的概率。
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
FULLWIDTH_URL_SYMBOLS = {"：", "／", "？", "＃", "＠", "［", "］", "（", "）", "．", "，", "＆", "＝", "％"}

def normalize_input_scheme(raw_url: str) -> str:
    """把 URL 协议前缀统一成小写。"""
    stripped = raw_url.strip()
    lowered = stripped.lower()
    if lowered.startswith("https://"):
        return "https://" + stripped[8:]
    if lowered.startswith("http://"):
        return "http://" + stripped[7:]
    return stripped


def has_hidden_url_chars(value: str) -> bool:
    """判断字符串中是否包含零宽或控制字符。"""
    for ch in value:
        if ch.isspace():
            return True
        if unicodedata.category(ch).startswith("C"):
            return True
    return False


def is_valid_host(host: str) -> bool:
    """判断主机名是否是合法的域名或 IP。"""
    if not host:
        return False

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_unspecified:
            return False
        if ip.version == 4 and int(ip) >= int(ipaddress.IPv4Address("224.0.0.0")):
            return False
        return True
    except ValueError:
        pass

    if host.replace(".", "").isdigit():
        return False

    if len(host) > 253:
        return False

    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not label[0].isalnum() or not label[-1].isalnum():
            return False
        if any(ch not in string.ascii_letters + string.digits + "-" for ch in label):
            return False
    return True


def validate_input_url(raw_url: str) -> Tuple[bool, str]:
    """校验输入的 URL。"""
    if not raw_url or not raw_url.strip():
        return False, "URL 不能为空"

    candidate = normalize_input_scheme(raw_url)
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False, "URL 格式不正确，请检查是否包含全角符号或其他非法字符。或确认是否为有效的IPv4/IPv6地址或域名。"

    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return False, "URL 仅支持 http 和 https 协议"

    if has_hidden_url_chars(candidate):
        return False, "URL 中包含空格、零宽字符或其他不可见字符，请删除后重试"
    if any(ch in FULLWIDTH_URL_SYMBOLS for ch in candidate):
        return False, "URL 中包含全角(中文)符号，请改用半角(英文)符号，例如 : / . [ ]"
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False, "URL 格式不正确，请检查是否包含全角符号或其他非法字符。或确认是否为有效的IPv4/IPv6地址或域名。"

    if parsed.username or parsed.password:
        return False, "URL 中不支持用户名或密码，请只输入主机地址"

    if not parsed.hostname:
        return False, "URL 格式不正确，请输入类似 example.com 或 https://example.com 或合法的 IP 地址，IPv6 地址请加上中括号"

    try:
        _ = parsed.port
    except ValueError:
        return False, "URL 中的端口号不正确"

    if not is_valid_host(parsed.hostname):
        return False, "该地址无效"

    return True, ""


def make_session() -> requests.Session:
    """创建带默认请求头的会话。"""
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    return session


def http_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs,
) -> requests.Response:
    """发送 HTTP 请求。"""
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    allow_redirects = kwargs.pop("allow_redirects", True)
    raise_for_status = kwargs.pop("raise_for_status", False)
    response = session.request(
        method=method,
        url=url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        **kwargs,
    )
    if raise_for_status:
        response.raise_for_status()
    return response


def normalize_url(raw_url: str, session: requests.Session) -> str:
    """补全并选择可访问的 URL 协议。"""
    raw_url = normalize_input_scheme(raw_url)

    parsed = urlparse(raw_url)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise ValueError("URL 仅支持 http 和 https 协议")

    if raw_url.startswith(("http://", "https://")):
        return raw_url

    https_url = "https://" + raw_url
    http_url = "http://" + raw_url

    try:
        http_request(session, "GET", https_url)
        return https_url
    except requests.RequestException:
        return http_url

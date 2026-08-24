"""用户 URL 输入校验测试。"""

import pytest

from utils.net import validate_input_url


@pytest.mark.parametrize(
    "value",
    ["example.com", "https://example.com/path", "203.0.113.1:8080", "[2001:db8::1234]:8443"],
)
def test_validate_input_url_accepts_supported_hosts_and_addresses(value: str) -> None:
    """域名、IPv4 与带方括号的 IPv6 应被接受。"""
    assert validate_input_url(value) == (True, "")


@pytest.mark.parametrize(
    ("value", "message_fragment"),
    [
        ("", "URL 不能为空"),
        ("ftp://example.com", "URL 仅支持 http 和 https 协议"),
        ("https://user:pass@example.com", "URL 中不支持用户名或密码"),
        ("https://example.com:invalid", "URL 中的端口号不正确"),
        ("0.0.0.0", "该地址无效"),
        ("https：//example.com", "URL 中包含全角(中文)符号"),
        ("https://example.com/with space", "URL 中包含空格、零宽字符或其他不可见字符"),
    ],
)
def test_validate_input_url_rejects_invalid_or_unsupported_input(
    value: str, message_fragment: str
) -> None:
    """非法协议、凭据、端口、地址与隐藏字符必须被拒绝。"""
    valid, message = validate_input_url(value)
    assert valid is False
    assert message_fragment in message

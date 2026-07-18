import requests
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, Tuple, List

from .options import ScanOptions


# 统一 HTTP 配置
DEFAULT_TIMEOUT = 5
DEFAULT_HEADERS = {
    "User-Agent": "WebGuardian/1.0 (+Security Scanner)"
}
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
SENSITIVE_PATHS = ["/admin", "/backup", "/test"]
COMMON_PORTS = [80, 443]


def _make_session() -> requests.Session:
    """
    创建统一 Session,复用 TCP 连接，提升稳定性和性能。
    """
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    return session


def http_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs
) -> requests.Response:
    """
    统一 HTTP 请求入口，集中处理超时、重定向等公共参数。
    """
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    allow_redirects = kwargs.pop("allow_redirects", True)
    return session.request(
        method=method,
        url=url,
        timeout=timeout,
        allow_redirects=allow_redirects,
        **kwargs
    )


def validate_input_url(raw_url: str) -> Tuple[bool, str]:
    """
    基础输入校验：
    1. 不能为空
    2. 去掉两端空白
    3. 协议可省略，但 host 必须可解析
    """
    if not raw_url or not raw_url.strip():
        return False, "URL 不能为空"

    candidate = raw_url.strip()

    # 若无协议，先补一个用于解析
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    if not parsed.netloc:
        return False, "URL 格式不正确，请输入类似 example.com 或 https://example.com"

    return True, ""


def normalize_url(raw_url: str, session: requests.Session) -> str:
    """
    URL 规范化：
    - 用户已写协议：直接返回
    - 未写协议：优先 https,失败回退 http
    """
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


def check_https(url: str) -> bool:
    return url.startswith("https://")


def check_ssl_via_requests(response: requests.Response) -> Tuple[bool, int]:
    """
    不使用 socket 直连，改为基于 requests 已建立连接判断 SSL 证书。
    说明：
    - 对于 https 请求，如果 TLS 握手成功,通常可认为证书链校验通过(verify=True 默认开启）
    - 可尝试读取证书到期时间；若取不到则返回天数 -1
    """
    try:
        if not response.url.startswith("https://"):
            return False, -1

        # 尝试读取证书信息（不同环境下对象层级可能不同）
        cert = None
        try:
            cert = response.raw.connection.sock.getpeercert()
        except Exception:
            cert = None

        if not cert:
            # HTTPS 请求成功但拿不到证书详情，依然视为 SSL 有效
            return True, -1

        not_after = cert.get("notAfter")
        if not not_after:
            return True, -1

        expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_dt - datetime.utcnow()).days
        return True, days_left
    except Exception:
        return False, -1


def calculate_score(result: Dict[str, Any], options: ScanOptions) -> Tuple[int, str]:
    """
    将评分逻辑独立，便于后续调整权重。
    """
    score = 0
    max_score = 0

    if options.check_https:
        max_score += 10
        if result.get("https"):
            score += 10

    if options.check_ssl:
        max_score += 20
        if result.get("ssl_valid"):
            score += 10

        days_left = result.get("ssl_days_left", -1)
        if isinstance(days_left, int) and days_left > 7:
            score += 10

    if options.check_security_headers:
        max_score += 30
        # 每个安全头 5 分，最多 30 分
        header_score = result.get("security_header_score", 0) or 0
        score += header_score

    if options.check_info_leak:
        max_score += 20
        info_leak = result.get("info_leak", {})
        if info_leak.get("server_header_exists") is False:
            score += 10
        if info_leak.get("x_powered_by_exists") is False:
            score += 10

    if options.check_trace:
        max_score += 10
        if result.get("trace_enabled") is False:
            score += 10

    if options.check_sensitive_paths:
        max_score += 10
        if not result.get("sensitive_paths"):
            score += 10

    if options.check_ports:
        max_score += 10
        open_ports = result.get("open_ports", []) or []
        if 443 in open_ports:
            score += 5
        if 80 in open_ports:
            score += 5

    if max_score > 0:
        score = round((score / max_score) * 100)

    if score >= 85:
        level = "A级"
    elif score >= 70:
        level = "B级"
    else:
        level = "C级"

    return score, level


def scan(url: str, progress_callback=None, options: Dict[str, Any] | ScanOptions | None = None) -> Dict[str, Any]:
    """
    核心扫描入口。
    progress_callback: 可选回调，供 UI 展示进度。
    """
    scan_options = options if isinstance(options, ScanOptions) else ScanOptions.from_dict(options)

    if scan_options.enabled_items() == 0:
        return {
            "ok": False,
            "error": "请至少启用一项检测后再开始扫描。",
        }

    def update_progress(p: int, text: str):
        if progress_callback:
            progress_callback(p, text)

    session = _make_session()
    errors: List[str] = []

    ok, msg = validate_input_url(url)
    if not ok:
        return {"ok": False, "error": msg}

    # URL 规范化（https 优先，失败回退 http）
    normalized_url = normalize_url(url, session)
    parsed = urlparse(normalized_url)
    host = parsed.hostname or ""

    result: Dict[str, Any] = {
        "ok": True,
        "url": normalized_url,
        "host": host,
        "https": False,
        "ssl_valid": False,
        "ssl_days_left": -1,
        "security_header_score": 0,
        "missing_security_headers": [],
        "trace_enabled": None,
        "sensitive_paths": [],
        "open_ports": [],
        "info_leak": {
            "server_header_exists": None,
            "x_powered_by_exists": None
        },
        "errors": []
    }

    # 1. 主请求
    update_progress(10, "正在请求目标站点")
    try:
        resp = http_request(session, "GET", normalized_url, stream=True)
    except Exception as e:
        return {"ok": False, "error": f"目标站点不可访问：{e}"}

    # 2. HTTPS / SSL
    update_progress(25, "正在检测 HTTPS 与 SSL")
    if scan_options.check_https:
        result["https"] = check_https(resp.url)
    else:
        result["https"] = None

    if scan_options.check_ssl:
        ssl_valid, ssl_days_left = check_ssl_via_requests(resp)
        result["ssl_valid"] = ssl_valid
        result["ssl_days_left"] = ssl_days_left
    else:
        result["ssl_valid"] = None
        result["ssl_days_left"] = None

    # 3. 安全响应头 + 信息泄露
    update_progress(45, "正在检测 HTTP 安全头与信息泄露")
    headers = resp.headers
    if scan_options.check_security_headers:
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        result["missing_security_headers"] = missing
        result["security_header_score"] = (len(SECURITY_HEADERS) - len(missing)) * 5
    else:
        result["missing_security_headers"] = None
        result["security_header_score"] = None

    if scan_options.check_info_leak:
        result["info_leak"]["server_header_exists"] = "Server" in headers
        result["info_leak"]["x_powered_by_exists"] = "X-Powered-By" in headers
    else:
        result["info_leak"]["server_header_exists"] = None
        result["info_leak"]["x_powered_by_exists"] = None

    # 4. TRACE 检测
    update_progress(60, "正在检测 TRACE 方法")
    if scan_options.check_trace:
        try:
            trace_resp = http_request(session, "TRACE", normalized_url, allow_redirects=False)
            result["trace_enabled"] = trace_resp.status_code < 400
        except Exception as e:
            result["trace_enabled"] = None
            errors.append(f"TRACE 检测异常：{e}")
    else:
        result["trace_enabled"] = None

    # 5. 敏感路径检测
    update_progress(75, "正在检测敏感路径")
    if scan_options.check_sensitive_paths:
        found_paths = []
        base = f"{parsed.scheme}://{parsed.netloc}"
        for p in SENSITIVE_PATHS:
            test_url = base + p
            try:
                r = http_request(session, "GET", test_url, allow_redirects=False)
                if r.status_code in (200, 301, 302, 401, 403):
                    found_paths.append(p)
            except Exception as e:
                errors.append(f"敏感路径 {p} 检测异常：{e}")
        result["sensitive_paths"] = found_paths
    else:
        result["sensitive_paths"] = None

    # 6. 端口检测（沿用你原有逻辑时请确保有 timeout）
    # 这里示例仅按 URL 协议推断常见端口可达性，避免引入 socket 复杂性
    update_progress(90, "正在整理端口与评分")
    if scan_options.check_ports:
        open_ports = []
        if parsed.scheme == "https":
            open_ports.append(443)
        if parsed.scheme == "http":
            open_ports.append(80)
        result["open_ports"] = open_ports
    else:
        result["open_ports"] = None

    # 7. 评分
    score, level = calculate_score(result, scan_options)
    result["score"] = score
    result["level"] = level

    result["errors"] = errors
    update_progress(100, "检测完成")
    return result

"""扫描领域结果模型。

这里定义扫描运行态、扫描结果和展示模型。检测模块的具体 payload 仍然
保留为 JSON 兼容对象，但不再用 ``Any`` 作为核心结果的通用类型。
"""

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Generic, TypeAlias, TypedDict, TypeVar, cast
from urllib.parse import ParseResult

import requests

from scanner.options import ScanOptions
from runtime.scan_progress import ScanProgress

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
JsonDocument: TypeAlias = dict[str, JsonValue]

class SectionStatus(str, Enum):
    """检测 section 的执行状态。"""

    OK = "ok"
    WARN = "warn"
    DISABLED = "disabled"
    SKIPPED = "skipped"
    ERROR = "error"

    @classmethod
    def from_value(
        cls, value: object, default: "SectionStatus | None" = None
    ) -> "SectionStatus":
        """把边界上的状态值转换为统一 section 状态。"""
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value))
        except ValueError:
            return default if default is not None else cls.OK


class Finding(TypedDict, total=False):
    """扫描发现项的公共字段。

    各检测模块可以保留自己的附加 JSON 字段；公共字段在这里获得稳定类型。
    """

    risk: str
    type: str
    kind: str
    field: str
    value: str
    url: str
    source: str
    path: str
    action: str
    message: str
    suggestion: str


class PageScanSummaryData(TypedDict):
    enabled: bool
    pages_scanned: int
    finding_count: int
    risk_counts: dict[str, int]
    highest_risk: str


@dataclass(frozen=True)
class FindingView:
    """发现项在结果页展示时使用的稳定字段。"""

    risk: str = "低"
    type: str = "发现项"
    field: str = ""
    value: str = ""
    url: str = ""
    source: str = ""
    path: str = ""
    message: str = ""
    suggestion: str = ""


@dataclass(frozen=True)
class AvailabilityViewData:
    """网站可用性展示数据。"""

    dns_seconds: float | None = None
    tcp_connect_seconds: float | None = None
    tls_handshake_seconds: float | None = None
    ttfb_seconds: float | None = None
    total_bytes: int | None = None


@dataclass(frozen=True)
class CipherViewData:
    """TLS 协商加密套件展示数据。"""

    cipher_name: str = ""
    cipher_bits: int = 0


@dataclass(frozen=True)
class CertificateViewData:
    """TLS 证书展示数据。"""

    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    serial_number: str = ""


@dataclass(frozen=True)
class TlsViewData:
    """TLS section 的展示数据。"""

    ssl_valid: bool | None = None
    ssl_days_left: int | None = None
    protocol: str = ""
    cipher: CipherViewData = field(default_factory=CipherViewData)
    certificate: CertificateViewData = field(default_factory=CertificateViewData)
    supported_protocols: list[str] = field(default_factory=lambda: list[str]())
    weak_protocols: list[str] = field(default_factory=lambda: list[str]())
    chain_length: int | None = None
    chain_complete: bool | None = None
    cipher_weak: bool | None = None


@dataclass(frozen=True)
class DnsRecordViewData:
    """单类 DNS 记录展示数据。"""

    present: bool | None = None
    records: list[str] = field(default_factory=lambda: list[str]())
    policy: str | None = None
    issuers: list[str] = field(default_factory=lambda: list[str]())


@dataclass(frozen=True)
class DnsViewData:
    """DNS section 的展示数据。"""

    domain: str = ""
    lookup_domain: str = ""
    spf: DnsRecordViewData = field(default_factory=DnsRecordViewData)
    dmarc: DnsRecordViewData = field(default_factory=DnsRecordViewData)
    caa: DnsRecordViewData = field(default_factory=DnsRecordViewData)


@dataclass(frozen=True)
class SecurityHeadersViewData:
    """安全响应头展示数据。"""

    score: int | None = None
    missing: list[str] = field(default_factory=lambda: list[str]())
    invalid: list[dict[str, str]] = field(default_factory=lambda: list[dict[str, str]]())


@dataclass(frozen=True)
class HttpMethodsViewData:
    """HTTP 方法检测展示数据。"""

    options_status: int | None = None
    allow_methods: list[str] = field(default_factory=lambda: list[str]())
    cors_methods: list[str] = field(default_factory=lambda: list[str]())
    exposed_methods: list[str] = field(default_factory=lambda: list[str]())
    trace_enabled: bool | None = None


@dataclass(frozen=True)
class InfoLeakViewData:
    """暴露信息检测展示数据。"""

    version_exposed: bool | None = None
    framework_exposed: bool | None = None
    meta_exposed: bool | None = None
    header_findings: list[FindingView] = field(default_factory=lambda: list[FindingView]())
    meta_fields: list[FindingView] = field(default_factory=lambda: list[FindingView]())


@dataclass(frozen=True)
class CrawlPolicyViewData:
    """robots.txt 展示数据。"""

    status: str = "未知"
    robots_url: str = ""
    allow_paths: list[str] = field(default_factory=lambda: list[str]())
    disallow_paths: list[str] = field(default_factory=lambda: list[str]())
    sitemap_urls: list[str] = field(default_factory=lambda: list[str]())
    findings: list[FindingView] = field(default_factory=lambda: list[FindingView]())
    warnings: list[str] = field(default_factory=lambda: list[str]())


@dataclass(frozen=True)
class SitemapViewData:
    """sitemap.xml 展示数据。"""

    status: str = "未知"
    sitemap_count: int = 0
    url_count: int = 0
    candidate_urls: list[str] = field(default_factory=lambda: list[str]())
    candidate_url_count: int | None = None
    candidate_urls_truncated: bool = False
    seed_urls: list[str] = field(default_factory=lambda: list[str]())
    seed_url_count: int | None = None
    seed_urls_truncated: bool = False
    findings: list[FindingView] = field(default_factory=lambda: list[FindingView]())
    finding_count: int | None = None
    findings_truncated: bool = False
    warnings: list[str] = field(default_factory=lambda: list[str]())


@dataclass(frozen=True)
class SiteCheckViewData:
    """robots.txt / sitemap.xml 汇总展示数据。"""

    enabled: bool = False
    status: str = "未知"
    robots_url: str = ""
    sitemap_url_count: int = 0
    finding_count: int = 0
    seed_url_count: int = 0
    highest_risk: str = "无"
    risk_counts: dict[str, int] = field(default_factory=lambda: dict[str, int]())
    crawl_policy: CrawlPolicyViewData = field(default_factory=CrawlPolicyViewData)
    sitemap: SitemapViewData = field(default_factory=SitemapViewData)


@dataclass(frozen=True)
class RedirectIssueViewData:
    """页面重定向问题展示数据。"""

    status_code: int = 0
    source: str = ""
    target: str = ""


@dataclass(frozen=True)
class PageScanViewData:
    """页面扫描 section 的展示数据。"""

    enabled: bool = False
    pages_scanned: int = 0
    pages_attempted: int = 0
    pages_failed: int = 0
    pages_skipped: int = 0
    assessment: str = "not_applicable"
    max_pages: int = 0
    max_depth: int = 0
    finding_count: int = 0
    highest_risk: str = "无"
    risk_counts: dict[str, int] = field(default_factory=lambda: dict[str, int]())
    message: str = ""
    sitecheck: SiteCheckViewData | None = None
    redirect_issues: list[RedirectIssueViewData] = field(
        default_factory=lambda: list[RedirectIssueViewData]()
    )


PayloadT = TypeVar("PayloadT")


@dataclass(frozen=True)
class SectionView(Generic[PayloadT]):
    """带有明确展示 payload 的 section。"""

    result: "SectionResult"
    data: PayloadT

    @property
    def enabled(self) -> bool | None:
        """返回 section 是否启用。"""
        return self.result.enabled

    @property
    def status(self) -> SectionStatus:
        """返回 section 执行状态。"""
        return self.result.status

    @property
    def warnings(self) -> list[str]:
        """返回 section 警告。"""
        return self.result.warnings

    @property
    def findings(self) -> list[FindingView]:
        """返回展示层发现项。"""
        return [finding_view(item) for item in self.result.findings]


@dataclass(frozen=True)
class ResultSections:
    """结果页需要的所有 typed section。"""

    availability: SectionView[AvailabilityViewData]
    https: SectionView[bool | None]
    tls: SectionView[TlsViewData]
    dns_security: SectionView[DnsViewData]
    security_headers: SectionView[SecurityHeadersViewData]
    http_methods: SectionView[HttpMethodsViewData]
    sensitive_paths: SectionView[list[str]]
    info_leak: SectionView[InfoLeakViewData]
    page_scan: SectionView[PageScanViewData]

    def to_dict(self) -> dict[str, JsonObject]:
        """返回 section 原始结构的序列化结果。"""
        return {
            name: section.result.to_dict()
            for name, section in (
                ("availability", self.availability),
                ("https", self.https),
                ("tls", self.tls),
                ("dns_security", self.dns_security),
                ("security_headers", self.security_headers),
                ("http_methods", self.http_methods),
                ("sensitive_paths", self.sensitive_paths),
                ("info_leak", self.info_leak),
                ("page_scan", self.page_scan),
            )
        }


@dataclass
class ScanContext:
    """保存一次扫描所需的目标和运行态信息。"""

    input_url: str
    normalized_url: str
    parsed: ParseResult
    host: str
    resolved_ips: list[str]
    scan_options: ScanOptions
    session: requests.Session
    progress: ScanProgress
    stop_event: threading.Event | None = None
    errors: list[str] = field(default_factory=lambda: [])


@dataclass(frozen=True)
class TargetResult:
    """扫描目标及其规范化信息。"""

    input_url: str = ""
    normalized_url: str = ""
    url: str = ""
    host: str = ""
    resolved_ips: list[str] = field(default_factory=lambda: [])

    def to_dict(self) -> JsonObject:
        """转换为保持现有结果结构的目标字典。"""
        return {
            "input_url": self.input_url,
            "normalized_url": self.normalized_url,
            "url": self.url,
            "host": self.host,
            "resolved_ips": list(self.resolved_ips),
        }


@dataclass(frozen=True)
class SectionResult:
    """一个检测 section 的元数据、消息、发现项和 JSON payload。"""

    name: str = ""
    enabled: bool | None = None
    status: SectionStatus = SectionStatus.OK
    summary: str = ""
    meta: JsonObject = field(default_factory=lambda: {})
    warnings: list[str] = field(default_factory=lambda: [])
    findings: list[Finding] = field(default_factory=lambda: [])
    data: JsonObject = field(default_factory=lambda: {})

    def to_dict(self) -> JsonObject:
        """转换为保持现有扁平 section 结构的结果字典。"""
        # 保持当前扁平 JSON 结构，兼容评分、原始结果和已有 UI。
        result: dict[str, object] = dict(self.data)
        result.update(
            {
                "name": self.name,
                "enabled": self.enabled,
                "status": self.status.value,
                "summary": self.summary,
                "meta": dict(self.meta),
                "warnings": list(self.warnings),
                "findings": list(self.findings),
            }
        )
        return cast(JsonObject, result)

    def value(self, key: str, default: JsonValue = None) -> JsonValue:
        """读取检测 payload 中的动态字段。"""

        return self.data.get(key, default)


@dataclass(frozen=True)
class ScoreItem:
    """一个基础模块的证据状态和评分依据。"""

    name: str
    label: str
    status: str
    earned: int | None
    maximum: int
    reason: str

    def to_dict(self) -> JsonObject:
        return {
            "name": self.name, "label": self.label, "status": self.status,
            "earned": self.earned, "maximum": self.maximum, "reason": self.reason,
        }


@dataclass(frozen=True)
class ScoreReport:
    """基础评分与本次检查范围；未完成的检查不产生正式评级。"""

    score: int | None = None
    level: str = "不适用"
    status: str = "not_applicable"
    enabled_count: int = 0
    evaluated_count: int = 0
    unknown_count: int = 0
    not_applicable_count: int = 0
    total_count: int = 7
    earned_points: int = 0
    possible_points: int = 0
    items: list[ScoreItem] = field(default_factory=lambda: list[ScoreItem]())

    def to_dict(self) -> JsonObject:
        return {
            "score": self.score, "level": self.level, "status": self.status,
            "enabled_count": self.enabled_count, "evaluated_count": self.evaluated_count,
            "unknown_count": self.unknown_count, "not_applicable_count": self.not_applicable_count,
            "total_count": self.total_count, "earned_points": self.earned_points,
            "possible_points": self.possible_points,
            "items": [item.to_dict() for item in self.items],
        }


@dataclass(frozen=True)
class Summary:
    """扫描摘要、模块耗时和页面扫描概览。"""

    score: int | None = None
    level: str = "未知"
    scoring: ScoreReport = field(default_factory=ScoreReport)
    elapsed_seconds: float | None = None
    module_durations: dict[str, float] = field(default_factory=lambda: {})
    page_scan_summary: PageScanSummaryData = field(
        default_factory=lambda: {
            "enabled": False,
            "pages_scanned": 0,
            "finding_count": 0,
            "risk_counts": {"低": 0, "中": 0, "高": 0},
            "highest_risk": "无",
        }
    )

    def to_dict(self) -> JsonObject:
        """转换为扫描摘要字典。"""
        return cast(JsonObject, {
            "score": self.score,
            "level": self.level,
            "scoring": self.scoring.to_dict(),
            "elapsed_seconds": self.elapsed_seconds,
            "module_durations": dict(self.module_durations),
            "page_scan_summary": dict(self.page_scan_summary),
        })


@dataclass(frozen=True)
class Messages:
    """扫描过程产生的错误和警告。"""

    errors: list[str] = field(default_factory=lambda: [])
    warnings: list[str] = field(default_factory=lambda: [])

    def to_dict(self) -> dict[str, list[str]]:
        """转换为错误和警告组成的消息字典。"""
        return {"errors": list(self.errors), "warnings": list(self.warnings)}


@dataclass(frozen=True)
class ScanResult:
    """一次扫描产生的领域结果。"""

    ok: bool
    target: TargetResult = field(default_factory=TargetResult)
    checks: dict[str, SectionResult] = field(default_factory=lambda: {})
    summary: Summary = field(default_factory=Summary)
    messages: Messages = field(default_factory=Messages)
    error: str | None = None

    def to_dict(self) -> JsonDocument:
        """转换为兼容原始结果格式的完整扫描字典。"""
        result: JsonDocument = {
            "ok": self.ok,
            "target": self.target.to_dict(),
            "checks": {
                name: section.to_dict() for name, section in self.checks.items()
            },
            "summary": self.summary.to_dict(),
            "errors": list(self.messages.errors),
            "warnings": list(self.messages.warnings),
        }
        if self.error is not None:
            result["error"] = self.error
        return result


@dataclass(frozen=True)
class OverviewViewModel:
    """结果页顶部概览。"""

    score: int | None
    level: str
    elapsed_seconds: float | None
    module_durations: dict[str, float]
    https: SectionView[bool | None]
    page_scan: PageScanViewData
    scoring: ScoreReport = field(default_factory=ScoreReport)


@dataclass(frozen=True)
class ScanViewModel:
    """Renderer 使用的稳定展示模型。"""

    overview: OverviewViewModel
    target: TargetResult
    sections: ResultSections
    messages: Messages
    raw: JsonDocument

    def to_dict(self) -> JsonObject:
        """转换为展示模型的可序列化字典。"""
        return cast(JsonObject, {
            "overview": {
                "score": self.overview.score,
                "level": self.overview.level,
                "scoring": self.overview.scoring.to_dict(),
                "elapsed_seconds": self.overview.elapsed_seconds,
                "module_durations": dict(self.overview.module_durations),
                "https": self.overview.https.result.to_dict(),
                "page_scan": _page_scan_view_to_dict(self.overview.page_scan),
            },
            "target": self.target.to_dict(),
            "sections": self.sections.to_dict(),
            "messages": self.messages.to_dict(),
            "raw": dict(self.raw),
        })


T = TypeVar("T")


def json_value(value: object, default: T) -> T:
    """在 JSON 边界将动态值收窄为调用方声明的类型。"""

    return cast(T, value) if value is not None else default


def mapping_or_empty(value: object) -> Mapping[str, JsonValue]:
    """把外部 JSON 值安全地收窄为映射。"""

    return cast(Mapping[str, JsonValue], value) if isinstance(value, Mapping) else {}


def finding_view(value: Finding) -> FindingView:
    """把可选字段的 JSON 发现项转换为稳定展示对象。"""
    return FindingView(
        risk=value.get("risk", "低"),
        type=value.get("type", value.get("kind", "发现项")),
        field=value.get("field", ""),
        value=value.get("value", ""),
        url=value.get("url", ""),
        source=value.get("source", ""),
        path=value.get("path", ""),
        message=value.get("message", ""),
        suggestion=value.get("suggestion", ""),
    )


def _page_scan_view_to_dict(value: PageScanViewData) -> JsonObject:
    """将页面扫描展示数据转换为 JSON 对象。"""
    return {
        "enabled": value.enabled,
        "pages_scanned": value.pages_scanned,
        "pages_attempted": value.pages_attempted,
        "pages_failed": value.pages_failed,
        "pages_skipped": value.pages_skipped,
        "assessment": value.assessment,
        "max_pages": value.max_pages,
        "max_depth": value.max_depth,
        "finding_count": value.finding_count,
        "highest_risk": value.highest_risk,
        "risk_counts": dict(value.risk_counts),
        "message": value.message,
        "sitecheck": (
            _sitecheck_view_to_dict(value.sitecheck)
            if value.sitecheck is not None
            else None
        ),
        "redirect_issues": [
            {
                "status_code": item.status_code,
                "from": item.source,
                "to": item.target,
            }
            for item in value.redirect_issues
        ],
    }


def _sitecheck_view_to_dict(value: SiteCheckViewData) -> JsonObject:
    """将站点公开入口展示数据转换为 JSON 对象。"""
    return {
        "enabled": value.enabled,
        "status": value.status,
        "robots_url": value.robots_url,
        "sitemap_url_count": value.sitemap_url_count,
        "finding_count": value.finding_count,
        "seed_url_count": value.seed_url_count,
        "highest_risk": value.highest_risk,
        "risk_counts": dict(value.risk_counts),
        "crawl_policy": _crawl_policy_view_to_dict(value.crawl_policy),
        "sitemap": _sitemap_view_to_dict(value.sitemap),
    }


def _crawl_policy_view_to_dict(value: CrawlPolicyViewData) -> JsonObject:
    """将 robots.txt 展示数据转换为 JSON 对象。"""
    return {
        "status": value.status,
        "robots_url": value.robots_url,
        "allow_paths": list(value.allow_paths),
        "disallow_paths": list(value.disallow_paths),
        "sitemap_urls": list(value.sitemap_urls),
        "findings": [_finding_view_to_dict(item) for item in value.findings],
        "warnings": list(value.warnings),
    }


def _sitemap_view_to_dict(value: SitemapViewData) -> JsonObject:
    """将 sitemap.xml 展示数据转换为 JSON 对象。"""
    return {
        "status": value.status,
        "sitemap_count": value.sitemap_count,
        "url_count": value.url_count,
        "candidate_urls": list(value.candidate_urls),
        "candidate_url_count": value.candidate_url_count,
        "candidate_urls_truncated": value.candidate_urls_truncated,
        "seed_urls": list(value.seed_urls),
        "seed_url_count": value.seed_url_count,
        "seed_urls_truncated": value.seed_urls_truncated,
        "findings": [_finding_view_to_dict(item) for item in value.findings],
        "finding_count": value.finding_count,
        "findings_truncated": value.findings_truncated,
        "warnings": list(value.warnings),
    }


def _finding_view_to_dict(value: FindingView) -> JsonObject:
    """将展示层发现项转换为 JSON 对象。"""
    return {
        "risk": value.risk,
        "type": value.type,
        "field": value.field,
        "value": value.value,
        "url": value.url,
        "source": value.source,
        "path": value.path,
        "message": value.message,
        "suggestion": value.suggestion,
    }

"""页面级扫描结果聚合。"""

from typing import Any, Dict, List


class PageScanResults:
    """汇总页面级扫描发现。"""

    def __init__(self) -> None:
        """初始化扫描结果。"""
        self.findings: List[Dict[str, Any]] = []
        self.risk_counts = {"低": 0, "中": 0, "高": 0}
        self.highest_risk = "无"
        self.sitecheck: Dict[str, Any] | None = None
        self.redirect_issues: List[Dict[str, Any]] = []
        self.redirect_chains: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.diagnostics: List[Dict[str, Any]] = []
        self.cookie_checks: List[Dict[str, Any]] = []

    def add_finding(
        self, risk: str, finding_type: str, url: str, message: str, suggestion: str,
        *, evidence: Dict[str, Any] | None = None,
    ) -> None:
        """记录一条页面发现。"""
        finding: Dict[str, Any] = {"url": url, "risk": risk, "type": finding_type, "message": message, "suggestion": suggestion}
        if evidence is not None:
            finding["evidence"] = evidence
        self.findings.append(finding)
        if risk not in self.risk_counts:
            return
        self.risk_counts[risk] += 1
        order = {"低": 0, "中": 1, "高": 2}
        if self.highest_risk == "无" or order[risk] > order[self.highest_risk]:
            self.highest_risk = risk

    def to_dict(
        self, pages_scanned: int, max_pages: int, max_depth: int, scanned_urls: List[str],
        message: str | None = None, *, pages_attempted: int | None = None,
        pages_failed: int = 0, pages_skipped: int = 0, assessment: str = "complete",
    ) -> Dict[str, Any]:
        """导出页面扫描结果。"""
        return {
            "enabled": True, "pages_scanned": pages_scanned, "max_pages": max_pages,
            "pages_attempted": pages_scanned if pages_attempted is None else pages_attempted,
            "pages_failed": pages_failed, "pages_skipped": pages_skipped,
            "assessment": assessment,
            "max_depth": max_depth, "finding_count": len(self.findings),
            "page_findings": len(self.findings), "highest_risk": self.highest_risk,
            "findings": self.findings, "risk_counts": self.risk_counts,
            "sitecheck": self.sitecheck,
            "visited_urls": scanned_urls, "redirect_issues": self.redirect_issues,
            "redirect_chains": self.redirect_chains, "warnings": self.warnings,
            "diagnostics": self.diagnostics, "cookie_checks": self.cookie_checks,
            "message": message,
        }

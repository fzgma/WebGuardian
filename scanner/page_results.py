"""页面级扫描结果聚合。"""

from typing import Any, Dict, List


class PageScanResults:
    """汇总页面级扫描发现。"""

    def __init__(self) -> None:
        """初始化扫描结果。"""
        self.findings: List[Dict[str, Any]] = []
        self.risk_counts = {"低": 0, "中": 0, "高": 0}
        self.highest_risk = "无"
        self.redirect_issues: List[Dict[str, Any]] = []
        self.redirect_chains: List[Dict[str, Any]] = []
        self.warnings: List[str] = []

    def add_finding(self, risk: str, finding_type: str, url: str, message: str, suggestion: str) -> None:
        """记录一条页面发现。"""
        self.findings.append({"url": url, "risk": risk, "type": finding_type, "message": message, "suggestion": suggestion})
        if risk not in self.risk_counts:
            return
        self.risk_counts[risk] += 1
        order = {"低": 0, "中": 1, "高": 2}
        if self.highest_risk == "无" or order[risk] > order[self.highest_risk]:
            self.highest_risk = risk

    def to_dict(self, pages_scanned: int, max_pages: int, max_depth: int, scanned_urls: List[str], message: str | None = None) -> Dict[str, Any]:
        """导出页面扫描结果。"""
        return {
            "enabled": True, "pages_scanned": pages_scanned, "max_pages": max_pages,
            "max_depth": max_depth, "finding_count": len(self.findings),
            "page_findings": len(self.findings), "highest_risk": self.highest_risk,
            "findings": self.findings, "risk_counts": self.risk_counts,
            "visited_urls": scanned_urls, "redirect_issues": self.redirect_issues,
            "redirect_chains": self.redirect_chains, "warnings": self.warnings,
            "message": message,
        }

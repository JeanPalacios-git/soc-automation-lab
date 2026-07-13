"""
SOC analysis report model.
"""

from dataclasses import dataclass

from soc_tool.models.finding import Finding


@dataclass
class Report:
    """Represent a SOC analysis report."""

    title: str
    generated_at: str
    findings: list[Finding]

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def high_findings(self) -> int:
        return sum(
            finding.severity == "HIGH"
            for finding in self.findings
        )

    @property
    def medium_findings(self) -> int:
        return sum(
            finding.severity == "MEDIUM"
            for finding in self.findings
        )

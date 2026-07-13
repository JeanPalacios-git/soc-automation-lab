"""
SOC analysis report model.
"""

from dataclasses import dataclass
from datetime import datetime

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

    @property
    def generated_at_display(self) -> str:
        timestamp = datetime.fromisoformat(self.generated_at)

        return timestamp.strftime(
            "%Y-%m-%d %H:%M:%S Costa Rica"
        )

    @property
    def affected_agents(self) -> list[str]:
        agents = {
            alert.agent_name
            for finding in self.findings
            for alert in finding.related_alerts
            if alert.agent_name
        }

        return sorted(agents)


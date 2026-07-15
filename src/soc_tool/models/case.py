"""
Security case model.
"""

from dataclasses import dataclass, field

from soc_tool.models.finding import Finding


@dataclass
class Case:
    """
    Represents a group of related security findings
    that should be investigated together.
    """

    case_id: str
    title: str
    severity: str
    findings: list[Finding]
    status: str = "Open"
    timeline: list[dict] = field(default_factory=list)
    entities: dict = field(default_factory=dict)
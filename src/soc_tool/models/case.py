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
    @property
    def mitre_techniques(self) -> list[str]:
        techniques = []

        for finding in self.findings:
            if finding.mitre_id:
                techniques.append(
                    finding.mitre_id
                )

        return sorted(
            set(techniques)
        )


    @property
    def recommendations(self) -> list[str]:
        recommendations = []

        for finding in self.findings:
            recommendations.append(
                finding.recommendation
            )

        return sorted(
            set(recommendations)
        )


    @property
    def attack_story(self) -> str:

        events = [
            finding.title
            for finding in self.findings
        ]

        if (
            "User Account Created" in events
            and
            "Privileged Group Membership Changed" in events
            and
            "Suspicious PowerShell" in events
        ):
            return (
                "A new account was created, granted "
                "privileged access, and followed by "
                "suspicious PowerShell execution. "
                "This pattern may indicate privileged "
                "account abuse."
            )

        if (
            "Linux User Account Created" in events
            and
            "Linux Privileged Group Membership Changed" in events
            and
            "Linux Failed Sudo Activity" in events
        ):
            return (
                "A Linux account was created, granted "
                "sudo privileges, and followed by failed "
                "privileged execution attempts. "
                "This may indicate Linux privilege "
                "escalation activity."
            )

        if (
            "Possible Brute Force" in events
            and
            "Suspicious PowerShell" in events
        ):
            return (
                "Multiple failed authentication attempts "
                "were followed by suspicious PowerShell "
                "execution on the same host. This pattern "
                "may indicate successful compromise "
                "followed by command execution."
            )

        if (
            "Linux SSH Brute Force" in events
            and
            "Linux Failed Sudo Activity" in events
        ):
            return (
                "Repeated SSH authentication failures "
                "were followed by failed sudo privilege "
                "escalation attempts on the same Linux host. "
                "This pattern may indicate attempted "
                "unauthorized access."
            )

        return (
            "Multiple related security findings were "
            "correlated into this investigation case."
        )



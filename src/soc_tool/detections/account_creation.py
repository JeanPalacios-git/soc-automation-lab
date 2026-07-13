"""
Account creation detection logic.
"""

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class AccountCreationDetector:
    """
    Detect Windows domain account creation events.
    """

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect Windows Event ID 4720.
        """

        findings = []

        for alert in alerts:
            if alert.event_id != "4720":
                continue

            findings.append(
                Finding(
                    title="User Account Created",
                    severity="MEDIUM",
                    mitre_id="T1136.002",
                    description=(
                        "A Windows domain user account was created."
                    ),
                    recommendation=(
                        "Verify that the account creation was authorized "
                        "and review the creator and assigned privileges."
                    ),
                    evidence={
                        "created_user": alert.username or "Unknown",
                        "created_by": alert.subject_username or "Unknown",
                        "target_domain": alert.target_domain or "Unknown",
                    },
                    related_alerts=[alert],
                )
            )

        return findings

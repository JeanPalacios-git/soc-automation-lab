"""
Account creation detection logic.
"""

from soc_tool.models.alert import Alert


class AccountCreationDetector:
    """
    Detect Windows user account creation events.
    """

    def detect(self, alerts: list[Alert]) -> list[dict]:
        """
        Detect Windows Event ID 4720.
        """

        findings = []

        for alert in alerts:
            if alert.event_id != "4720":
                continue

            findings.append(
                {
                    "detection": "User Account Created",
                    "agent_name": alert.agent_name,
                    "created_user": alert.username or "Unknown",
                    "created_by": alert.subject_username or "Unknown",
                    "target_domain": alert.target_domain or "Unknown",
                    "timestamp": alert.timestamp,
                }
            )

        return findings
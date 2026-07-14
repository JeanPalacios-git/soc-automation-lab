"""
Linux user account creation detection logic.
"""

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class LinuxUserCreationDetector:
    """
    Detect Linux user account creation.
    """

    RULE_ID = "5902"

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect new Linux user accounts reported by Wazuh.
        """

        findings = []

        for alert in alerts:
            if alert.rule_id != self.RULE_ID:
                continue

            data = alert.raw_data.get("data") or {}

            findings.append(
                Finding(
                    title="Linux User Account Created",
                    severity="MEDIUM",
                    mitre_id="T1136",
                    description=(
                        "A new local user account was created on "
                        "a Linux host."
                    ),
                    recommendation=(
                        "Validate that the account creation was "
                        "authorized and review the account owner, "
                        "shell, home directory, and assigned IDs."
                    ),
                    evidence={
                        "username": data.get(
                            "dstuser",
                            "Unknown",
                        ),
                        "uid": data.get(
                            "uid",
                            "Unknown",
                        ),
                        "gid": data.get(
                            "gid",
                            "Unknown",
                        ),
                        "home": data.get(
                            "home",
                            "Unknown",
                        ),
                        "shell": data.get(
                            "shell",
                            "Unknown",
                        ),
                    },
                    related_alerts=[alert],
                )
            )

        return findings

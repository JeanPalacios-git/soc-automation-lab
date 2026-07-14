"""
Linux failed sudo detection logic.
"""

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class LinuxFailedSudoDetector:
    """
    Detect repeated failed sudo authentication attempts.
    """

    RULE_ID = "5404"

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect Wazuh failed sudo alerts.
        """

        findings = []

        for alert in alerts:
            if alert.rule_id != self.RULE_ID:
                continue

            data = alert.raw_data.get("data") or {}

            findings.append(
                Finding(
                    title="Linux Failed Sudo Activity",
                    severity="HIGH",
                    mitre_id="T1548.003",
                    description=(
                        "Repeated failed sudo authentication "
                        "attempts were detected on a Linux host."
                    ),
                    recommendation=(
                        "Review the requesting user and attempted "
                        "privileged command. Validate whether the "
                        "sudo activity was authorized."
                    ),
                    evidence={
                        "source_user": data.get(
                            "srcuser",
                            "Unknown",
                        ),
                        "target_user": data.get(
                            "dstuser",
                            "Unknown",
                        ),
                        "command": data.get(
                            "command",
                            "Unknown",
                        ),
                        "tty": data.get(
                            "tty",
                            "Unknown",
                        ),
                        "working_directory": data.get(
                            "pwd",
                            "Unknown",
                        ),
                    },
                    related_alerts=[alert],
                )
            )

        return findings

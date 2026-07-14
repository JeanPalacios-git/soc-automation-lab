"""
Linux SSH brute force detection logic.
"""

import re

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class LinuxSSHBruteForceDetector:
    """
    Detect Wazuh-correlated SSH brute force activity.
    """

    RULE_ID = "2502"

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect correlated SSH authentication failures.
        """

        findings = []

        for alert in alerts:
            if alert.rule_id != self.RULE_ID:
                continue

            full_log = str(
                alert.raw_data.get("full_log", "")
            )

            source_match = re.search(
                r"rhost=([^\s]+)",
                full_log,
            )

            source_ip = (
                source_match.group(1)
                if source_match
                else "Unknown"
            )

            predecoder = (
                alert.raw_data.get("predecoder") or {}
            )

            rule = alert.raw_data.get("rule") or {}

            findings.append(
                Finding(
                    title="Linux SSH Brute Force",
                    severity="HIGH",
                    mitre_id="T1110",
                    description=(
                        "Repeated SSH authentication failures were "
                        "correlated by Wazuh on a Linux host."
                    ),
                    recommendation=(
                        "Investigate the source IP and review SSH "
                        "authentication activity for unauthorized "
                        "access attempts."
                    ),
                    evidence={
                        "source_ip": source_ip,
                        "service": predecoder.get(
                            "program_name",
                            "sshd",
                        ),
                        "wazuh_rule_id": alert.rule_id,
                        "wazuh_rule_description": rule.get(
                            "description",
                            "Unknown",
                        ),
                    },
                    related_alerts=[alert],
                )
            )

        return findings

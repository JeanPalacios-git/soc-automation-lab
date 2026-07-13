"""
Suspicious PowerShell detection logic.
"""

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class SuspiciousPowerShellDetector:
    """
    Detect suspicious PowerShell script block content.
    """

    SUSPICIOUS_PATTERNS = (
        "encodedcommand",
        "-enc",
        "invoke-webrequest",
        "downloadstring",
        "invoke-expression",
        "iex",
    )

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect suspicious patterns in PowerShell 4104 events.
        """

        findings = []

        for alert in alerts:
            if alert.event_id != "4104":
                continue

            if not alert.script_block_text:
                continue

            script_text = alert.script_block_text.lower()

            matched_patterns = [
                pattern
                for pattern in self.SUSPICIOUS_PATTERNS
                if pattern in script_text
            ]

            if not matched_patterns:
                continue

            findings.append(
                Finding(
                    title="Suspicious PowerShell",
                    severity="HIGH",
                    mitre_id="T1059.001",
                    description=(
                        "Suspicious PowerShell script block content "
                        "was detected."
                    ),
                    recommendation=(
                        "Review the script content and investigate the "
                        "host for malicious PowerShell activity."
                    ),
                    evidence={
                        "matched_patterns": matched_patterns,
                        "script_block_text": alert.script_block_text,
                    },
                    related_alerts=[alert],
                )
            )

        return findings

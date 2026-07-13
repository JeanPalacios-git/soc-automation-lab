"""
Suspicious PowerShell detection logic.
"""

from soc_tool.models.alert import Alert


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

    def detect(self, alerts: list[Alert]) -> list[dict]:
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
                {
                    "detection": "Suspicious PowerShell",
                    "agent_name": alert.agent_name,
                    "matched_patterns": matched_patterns,
                    "script_block_text": alert.script_block_text,
                    "timestamp": alert.timestamp,
                }
            )

        return findings
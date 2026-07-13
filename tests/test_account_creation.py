"""
Tests for account creation detection.
"""

from soc_tool.detections.account_creation import AccountCreationDetector
from soc_tool.models.alert import Alert


def create_alert(event_id: str) -> Alert:
    return Alert(
        timestamp="2026-07-01T10:00:00.000+0000",
        agent_name="DC01",
        rule_id="60143",
        rule_level=5,
        event_id=event_id,
        username="soctest",
        source_ip=None,
        script_block_text=None,
        subject_username="Administrator",
        target_domain="SOCLAB",
        member_name=None,
        event_record_id="17147",
        raw_data={},
    )


def test_detect_account_creation() -> None:
    detector = AccountCreationDetector()

    findings = detector.detect([
        create_alert("4720"),
    ])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "User Account Created"
    assert finding.severity == "MEDIUM"
    assert finding.mitre_id == "T1136.002"
    assert finding.evidence["created_user"] == "soctest"
    assert finding.evidence["created_by"] == "Administrator"
    assert finding.evidence["target_domain"] == "SOCLAB"


def test_ignore_non_account_creation_event() -> None:
    detector = AccountCreationDetector()

    findings = detector.detect([
        create_alert("4625"),
    ])

    assert findings == []

"""
Tests for account creation detection.
"""

from soc_tool.detections.account_creation import AccountCreationDetector
from soc_tool.models.alert import Alert


def create_alert(event_id: str) -> Alert:
    return Alert(
        timestamp="2026-07-05T07:56:01.892+0000",
        agent_name="DC01",
        rule_id="60109",
        rule_level=8,
        event_id=event_id,
        username="soctest",
        source_ip=None,
        event_record_id="3001",
        script_block_text=None,
        subject_username="Administrator",
        target_domain="SOCLAB",
        member_name=None,
        raw_data={},
    )


def test_detect_account_creation() -> None:
    detector = AccountCreationDetector()

    findings = detector.detect([
        create_alert("4720"),
    ])

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "User Account Created"
    assert finding["created_user"] == "soctest"
    assert finding["created_by"] == "Administrator"
    assert finding["target_domain"] == "SOCLAB"


def test_ignore_non_account_creation_event() -> None:
    detector = AccountCreationDetector()

    findings = detector.detect([
        create_alert("4625"),
    ])

    assert findings == []



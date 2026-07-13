"""
Tests for privileged group membership detection.
"""

from soc_tool.detections.group_membership import GroupMembershipDetector
from soc_tool.models.alert import Alert


def create_alert(event_id: str, group_name: str) -> Alert:
    return Alert(
        timestamp="2026-07-05T07:56:51.150+0000",
        agent_name="DC01",
        rule_id="60141",
        rule_level=5,
        event_id=event_id,
        username=group_name,
        source_ip=None,
        script_block_text=None,
        subject_username="Administrator",
        target_domain="SOCLAB",
        member_name="CN=SOC Test User,OU=Employees,DC=soclab,DC=local",
        event_record_id="19004",
        raw_data={},
    )


def test_detect_privileged_group_membership_change() -> None:
    detector = GroupMembershipDetector()

    findings = detector.detect([
        create_alert("4728", "Domain Admins"),
    ])

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "Privileged Group Membership Changed"
    assert finding["group_name"] == "Domain Admins"
    assert "SOC Test User" in finding["member_name"]
    assert finding["changed_by"] == "Administrator"


def test_ignore_non_privileged_group() -> None:
    detector = GroupMembershipDetector()

    findings = detector.detect([
        create_alert("4728", "GG_IT"),
    ])

    assert findings == []


def test_ignore_non_group_membership_event() -> None:
    detector = GroupMembershipDetector()

    findings = detector.detect([
        create_alert("4720", "Domain Admins"),
    ])

    assert findings == []

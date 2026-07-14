"""
Tests for Linux privileged group membership detection.
"""

from soc_tool.detections.linux_privileged_group import (
    LinuxPrivilegedGroupDetector,
)
from soc_tool.models.alert import Alert


def create_alert(
    rule_id: str = "80792",
    group: str = "sudo",
    success: str = "yes",
) -> Alert:
    return Alert(
        timestamp="2026-07-13T23:40:04.903+0000",
        agent_name="linux-01",
        rule_id=rule_id,
        rule_level=3,
        event_id=None,
        username=None,
        source_ip=None,
        event_record_id=None,
        member_name=None,
        script_block_text=None,
        subject_username=None,
        target_domain=None,
        raw_data={
            "data": {
                "audit": {
                    "exe": "/usr/sbin/usermod",
                    "command": "usermod",
                    "success": success,
                    "execve": {
                        "a1": "-aG",
                        "a2": group,
                        "a3": "SOC_LINUX_REAL",
                    },
                },
            },
        },
    )


def test_detect_privileged_group_change() -> None:
    findings = LinuxPrivilegedGroupDetector().detect(
        [create_alert()]
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "Linux Privileged Group Membership Changed"
    )
    assert findings[0].severity == "HIGH"
    assert findings[0].mitre_id == "T1098.007"
    assert (
        findings[0].evidence["target_user"]
        == "SOC_LINUX_REAL"
    )
    assert (
        findings[0].evidence["privileged_group"]
        == "sudo"
    )


def test_ignore_non_privileged_group() -> None:
    findings = LinuxPrivilegedGroupDetector().detect(
        [create_alert(group="developers")]
    )

    assert findings == []


def test_ignore_failed_usermod() -> None:
    findings = LinuxPrivilegedGroupDetector().detect(
        [create_alert(success="no")]
    )

    assert findings == []


def test_ignore_unrelated_rule() -> None:
    findings = LinuxPrivilegedGroupDetector().detect(
        [create_alert(rule_id="9999")]
    )

    assert findings == []

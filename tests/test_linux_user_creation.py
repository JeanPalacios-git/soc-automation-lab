"""
Tests for Linux user account creation detection.
"""

from soc_tool.detections.linux_user_creation import (
    LinuxUserCreationDetector,
)
from soc_tool.models.alert import Alert


def create_alert(rule_id: str = "5902") -> Alert:
    return Alert(
        timestamp="2026-07-13T23:36:42.814+0000",
        agent_name="linux-01",
        rule_id=rule_id,
        rule_level=8,
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
                "dstuser": "SOC_LINUX_REAL",
                "uid": "1001",
                "gid": "1001",
                "home": "/home/SOC_LINUX_REAL",
                "shell": "/bin/sh",
            },
        },
    )


def test_detect_linux_user_creation() -> None:
    findings = LinuxUserCreationDetector().detect(
        [create_alert()]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Linux User Account Created"
    )
    assert findings[0].severity == "MEDIUM"
    assert findings[0].mitre_id == "T1136"
    assert (
        findings[0].evidence["username"]
        == "SOC_LINUX_REAL"
    )
    assert findings[0].evidence["uid"] == "1001"


def test_ignore_unrelated_rule() -> None:
    findings = LinuxUserCreationDetector().detect(
        [create_alert("9999")]
    )

    assert findings == []

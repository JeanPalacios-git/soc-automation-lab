"""
Tests for Linux failed sudo detection.
"""

from soc_tool.detections.linux_failed_sudo import (
    LinuxFailedSudoDetector,
)
from soc_tool.models.alert import Alert


def create_alert(rule_id: str = "5404") -> Alert:
    return Alert(
        timestamp="2026-07-13T23:32:00.727+0000",
        agent_name="linux-01",
        rule_id=rule_id,
        rule_level=10,
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
                "srcuser": "yanots",
                "dstuser": "root",
                "tty": "pts/0",
                "pwd": "/home/yanots",
                "command": (
                    "/usr/sbin/useradd -m SOC_LINUX_TEST"
                ),
            },
        },
    )


def test_detect_linux_failed_sudo() -> None:
    findings = LinuxFailedSudoDetector().detect(
        [create_alert()]
    )

    assert len(findings) == 1
    assert findings[0].title == "Linux Failed Sudo Activity"
    assert findings[0].severity == "HIGH"
    assert findings[0].mitre_id == "T1548.003"
    assert findings[0].evidence["source_user"] == "yanots"
    assert findings[0].evidence["target_user"] == "root"


def test_ignore_unrelated_rule() -> None:
    findings = LinuxFailedSudoDetector().detect(
        [create_alert("9999")]
    )

    assert findings == []

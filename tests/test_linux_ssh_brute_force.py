"""
Tests for Linux SSH brute force detection.
"""

from soc_tool.detections.linux_ssh_brute_force import (
    LinuxSSHBruteForceDetector,
)
from soc_tool.models.alert import Alert


def create_alert(rule_id: str = "2502") -> Alert:
    return Alert(
        timestamp="2026-07-13T23:29:12.604+0000",
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
            "rule": {
                "id": "2502",
                "description": (
                    "syslog: User missed the password "
                    "more than one time"
                ),
            },
            "predecoder": {
                "program_name": "sshd",
            },
            "data": None,
            "full_log": (
                "PAM 2 more authentication failures; "
                "tty=ssh ruser= rhost=127.0.0.1"
            ),
        },
    )


def test_detect_linux_ssh_brute_force() -> None:
    findings = LinuxSSHBruteForceDetector().detect(
        [create_alert()]
    )

    assert len(findings) == 1
    assert findings[0].title == "Linux SSH Brute Force"
    assert findings[0].severity == "HIGH"
    assert findings[0].mitre_id == "T1110"
    assert findings[0].evidence["source_ip"] == "127.0.0.1"
    assert findings[0].evidence["service"] == "sshd"


def test_ignore_unrelated_rule() -> None:
    findings = LinuxSSHBruteForceDetector().detect(
        [create_alert("9999")]
    )

    assert findings == []

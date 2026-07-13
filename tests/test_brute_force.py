"""
Tests for brute force detection.
"""

from soc_tool.detections.brute_force import BruteForceDetector
from soc_tool.models.alert import Alert


def create_alert(timestamp: str) -> Alert:
    return Alert(
        timestamp=timestamp,
        agent_name="DC01",
        rule_id="60122",
        rule_level=5,
        event_id="4625",
        username="Administrator",
        source_ip="192.168.188.50",
        script_block_text=None,
        subject_username=None,
        target_domain="SOCLAB",
        member_name=None,
        event_record_id="17147",
        raw_data={},
    )


def test_detect_brute_force_within_time_window() -> None:
    alerts = [
        create_alert(f"2026-07-01T10:00:0{i}.000+0000")
        for i in range(5)
    ]

    detector = BruteForceDetector()

    findings = detector.detect(alerts)

    assert len(findings) == 1
    assert findings[0].title == "Possible Brute Force"
    assert findings[0].severity == "HIGH"
    assert findings[0].mitre_id == "T1110"
    assert findings[0].evidence["failed_attempts"] == 5


def test_ignore_failed_logons_outside_time_window() -> None:
    alerts = [
        create_alert("2026-07-01T10:00:00.000+0000"),
        create_alert("2026-07-01T10:10:00.000+0000"),
        create_alert("2026-07-01T10:20:00.000+0000"),
        create_alert("2026-07-01T10:30:00.000+0000"),
        create_alert("2026-07-01T10:40:00.000+0000"),
    ]

    detector = BruteForceDetector()

    findings = detector.detect(alerts)

    assert findings == []

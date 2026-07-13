"""
Tests for brute force detection.
"""

from soc_tool.detections.brute_force import BruteForceDetector
from soc_tool.models.alert import Alert


def create_failed_logon(timestamp: str) -> Alert:
    return Alert(
        timestamp=timestamp,
        agent_name="DC01",
        rule_id="60122",
        rule_level=5,
        event_id="4625",
        username="Administrator",
        source_ip="127.0.0.1",
        script_block_text=None,
        raw_data={},
    )


def test_detect_brute_force_within_time_window() -> None:
    detector = BruteForceDetector(
        threshold=5,
        window_minutes=5,
    )

    alerts = [
        create_failed_logon("2026-07-05T07:40:00.000+0000"),
        create_failed_logon("2026-07-05T07:41:00.000+0000"),
        create_failed_logon("2026-07-05T07:42:00.000+0000"),
        create_failed_logon("2026-07-05T07:43:00.000+0000"),
        create_failed_logon("2026-07-05T07:44:00.000+0000"),
    ]

    findings = detector.detect(alerts)

    assert len(findings) == 1
    assert findings[0]["failed_attempts"] == 5


def test_ignore_failed_logons_outside_time_window() -> None:
    detector = BruteForceDetector(
        threshold=5,
        window_minutes=5,
    )

    alerts = [
        create_failed_logon("2026-07-05T07:40:00.000+0000"),
        create_failed_logon("2026-07-05T07:50:00.000+0000"),
        create_failed_logon("2026-07-05T08:00:00.000+0000"),
        create_failed_logon("2026-07-05T08:10:00.000+0000"),
        create_failed_logon("2026-07-05T08:20:00.000+0000"),
    ]

    findings = detector.detect(alerts)

    assert findings == []
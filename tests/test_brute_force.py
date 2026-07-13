"""
Tests for brute force detection.
"""

from soc_tool.detections.brute_force import BruteForceDetector
from soc_tool.models.alert import Alert


def create_alert(
    timestamp: str,
    event_record_id: str,
) -> Alert:
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
        event_record_id=event_record_id,
        raw_data={},
    )


def test_detect_brute_force_within_time_window() -> None:
    alerts = [
        create_alert(
            f"2026-07-01T10:00:0{i}.000+0000",
            str(17147 + i),
        )
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
        create_alert(
            "2026-07-01T10:00:00.000+0000",
            "17147",
        ),
        create_alert(
            "2026-07-01T10:10:00.000+0000",
            "17148",
        ),
        create_alert(
            "2026-07-01T10:20:00.000+0000",
            "17149",
        ),
        create_alert(
            "2026-07-01T10:30:00.000+0000",
            "17150",
        ),
        create_alert(
            "2026-07-01T10:40:00.000+0000",
            "17151",
        ),
    ]

    detector = BruteForceDetector()

    findings = detector.detect(alerts)

    assert findings == []


def test_detect_independent_brute_force_campaigns() -> None:
    first_campaign = [
        create_alert(
            f"2026-07-01T09:22:4{i}.000+0000",
            str(18000 + i),
        )
        for i in range(5)
    ]

    second_campaign = [
        create_alert(
            f"2026-07-01T22:56:3{i}.000+0000",
            str(19000 + i),
        )
        for i in range(5)
    ]

    detector = BruteForceDetector()

    findings = detector.detect(
        first_campaign + second_campaign
    )

    assert len(findings) == 2

    assert (
        findings[0].evidence["first_seen"]
        == "2026-07-01T09:22:40.000+0000"
    )

    assert (
        findings[1].evidence["first_seen"]
        == "2026-07-01T22:56:30.000+0000"
    )

    assert findings[0].fingerprint != findings[1].fingerprint

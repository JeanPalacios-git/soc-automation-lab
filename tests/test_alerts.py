"""
Tests for the alert service.
"""

from soc_tool.api.alerts import AlertService
from soc_tool.models.alert import Alert


def test_get_recent_alerts() -> None:
    service = AlertService()

    alerts = service.get_recent(limit=5)

    assert len(alerts) == 5

    for alert in alerts:
        assert isinstance(alert, Alert)


def test_deduplicate_windows_events() -> None:
    duplicate_one = Alert(
        timestamp="2026-07-01T10:12:43.586+0000",
        agent_name="DC01",
        rule_id="60109",
        rule_level=8,
        event_id="4720",
        username="flower",
        source_ip=None,
        script_block_text=None,
        subject_username="Administrator",
        target_domain="SOCLAB",
        event_record_id="17147",
        raw_data={},
    )

    duplicate_two = Alert(
        timestamp="2026-07-01T10:12:43.586+0000",
        agent_name="DC01",
        rule_id="60109",
        rule_level=8,
        event_id="4720",
        username="flower",
        source_ip=None,
        script_block_text=None,
        subject_username="Administrator",
        target_domain="SOCLAB",
        event_record_id="17147",
        raw_data={},
    )

    alerts = AlertService._deduplicate([
        duplicate_one,
        duplicate_two,
    ])

    assert len(alerts) == 1
    assert alerts[0].username == "flower"
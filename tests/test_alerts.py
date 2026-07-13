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
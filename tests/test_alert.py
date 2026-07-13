"""
Tests for the Alert model.
"""

from soc_tool.models.alert import Alert


def test_alert_from_api() -> None:
    raw_alert = {
        "timestamp": "2026-07-13T05:52:32.856+0000",
        "agent": {
            "name": "JeanPc",
        },
        "rule": {
            "id": "92154",
            "level": 4,
        },
        "data": {
            "win": {
                "system": {
                    "eventID": "7",
                },
                "eventdata": {
                    "targetUserName": "testuser",
                },
            },
            "srcip": "192.168.188.50",
        },
    }

    alert = Alert.from_api(raw_alert)

    assert alert.timestamp == "2026-07-13T05:52:32.856+0000"
    assert alert.agent_name == "JeanPc"
    assert alert.rule_id == "92154"
    assert alert.rule_level == 4
    assert alert.event_id == "7"
    assert alert.username == "testuser"
    assert alert.source_ip == "192.168.188.50"
    assert alert.raw_data == raw_alert
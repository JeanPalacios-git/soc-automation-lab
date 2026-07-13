"""
Tests for the Wazuh API client.
"""

from soc_tool.api.client import WazuhClient


def test_get_manager_info() -> None:
    client = WazuhClient()

    response = client.get_manager_info()

    assert response["error"] == 0
    assert response["data"]["total_affected_items"] >= 1

    manager = response["data"]["affected_items"][0]

    assert manager["type"] == "server"
    assert "version" in manager
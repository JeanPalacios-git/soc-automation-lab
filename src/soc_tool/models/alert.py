from dataclasses import dataclass
from typing import Any


@dataclass
class Alert:
    """
    Represents a normalized security alert retrieved from Wazuh.
    """

    timestamp: str
    agent_name: str
    rule_id: int
    rule_level: str
    event_id: str | None
    username: str | None
    source_ip: str | None
    raw_data: dict[str, Any]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "Alert":
        """
        Create an Alert instance from a Wazuh API response.
        """

        return cls(
            timestamp=data.get("timestamp", ""),
            agent_name=data.get("agent", {}).get("name", "Unknown"),
            rule_id=data.get("rule", {}).get("id", ""),
            rule_level=data.get("rule", {}).get("level", 0),
            event_id=data.get("data", {}).get("win", {}).get("system", {}).get("eventID"),
            username=data.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName"),
            source_ip=data.get("data", {}).get("srcip"),
            raw_data=data,
        )
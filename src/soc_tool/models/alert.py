"""
Alert model.
"""

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Alert:
    """
    Represents a normalized security alert retrieved from Wazuh.
    """

    timestamp: str
    agent_name: str
    rule_id: str
    rule_level: int
    event_id: str | None
    username: str | None
    source_ip: str | None
    raw_data: dict[str, Any]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "Alert":
        """
        Create an Alert instance from a Wazuh API response.
        """

        agent = data.get("agent", {})
        rule = data.get("rule", {})
        win = data.get("data", {}).get("win", {})
        system = win.get("system", {})
        eventdata = win.get("eventdata", {})

        return cls(
            timestamp=data.get("timestamp", ""),
            agent_name=agent.get("name", "Unknown"),
            rule_id=str(rule.get("id", "")),
            rule_level=int(rule.get("level", 0)),
            event_id=system.get("eventID"),
            username=eventdata.get("targetUserName"),
            source_ip=data.get("data", {}).get("srcip"),
            raw_data=data,
        )
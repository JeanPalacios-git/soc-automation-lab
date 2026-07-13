"""
Security alert model.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
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
    script_block_text: str | None
    raw_data: dict[str, Any]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "Alert":
        """
        Create an Alert instance from a Wazuh alert document.
        """

        win_data = data.get("data", {}).get("win", {})
        event_data = win_data.get("eventdata", {})
        system_data = win_data.get("system", {})

        return cls(
            timestamp=data.get("timestamp", ""),
            agent_name=data.get("agent", {}).get("name", "Unknown"),
            rule_id=str(data.get("rule", {}).get("id", "")),
            rule_level=int(data.get("rule", {}).get("level", 0)),
            event_id=system_data.get("eventID"),
            username=event_data.get("targetUserName"),
            source_ip=(
                event_data.get("ipAddress")
                or data.get("data", {}).get("srcip")
            ),
            script_block_text=event_data.get("scriptBlockText"),
            raw_data=data,
        )
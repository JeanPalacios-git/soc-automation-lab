"""
Security alert model.
"""

from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo
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
    event_record_id: str | None
    member_name: str | None
    script_block_text: str | None
    subject_username: str | None
    target_domain: str | None
    raw_data: dict[str, Any]

    @property
    def timestamp_display(self) -> str:
        """Return the alert timestamp in Costa Rica local time."""

        timestamp = datetime.fromisoformat(self.timestamp)

        local_timestamp = timestamp.astimezone(
            ZoneInfo("America/Costa_Rica")
        )

        return local_timestamp.strftime(
            "%Y-%m-%d %H:%M:%S Costa Rica"
        )
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
            event_record_id=system_data.get("eventRecordID"),
            subject_username=event_data.get("subjectUserName"),
            member_name=event_data.get("memberName"),
            target_domain=event_data.get("targetDomainName"),
            raw_data=data,
        )

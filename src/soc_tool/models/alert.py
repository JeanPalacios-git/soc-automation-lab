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
    rule_level: int
    event_id: int | None
    username: str | None
    source_ip: str | None
    raw_data: dict[str, Any]
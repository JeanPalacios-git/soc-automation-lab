"""
Alert service.

Provides methods to retrieve and normalize alerts from the Wazuh Indexer.
"""

from soc_tool.api.indexer import WazuhIndexer
from soc_tool.models.alert import Alert


class AlertService:
    """
    Service responsible for retrieving and normalizing Wazuh alerts.
    """

    def __init__(self) -> None:
        self.indexer = WazuhIndexer()

    def get_recent(self, limit: int = 100) -> list[Alert]:
        """
        Retrieve the most recent Wazuh alerts.
        """

        query = {
            "size": limit,
            "sort": [
                {
                    "timestamp": {
                        "order": "desc",
                    }
                }
            ],
        }

        return self._search(query)

    def get_by_event_id(
        self,
        event_id: str,
        limit: int = 100,
    ) -> list[Alert]:
        """
        Retrieve Windows alerts matching an Event ID.
        """

        query = {
            "size": limit,
            "query": {
                "term": {
                    "data.win.system.eventID": event_id,
                }
            },
            "sort": [
                {
                    "timestamp": {
                        "order": "desc",
                    }
                }
            ],
        }

        return self._search(query)

    def _search(self, query: dict) -> list[Alert]:
        """
        Execute an alert search, normalize and deduplicate results.
        """

        response = self.indexer.search_alerts(query)

        alerts = [
            Alert.from_api(hit["_source"])
            for hit in response["hits"]["hits"]
        ]

        return self._deduplicate(alerts)

    @staticmethod
    def _deduplicate(alerts: list[Alert]) -> list[Alert]:
        """
        Remove duplicate Windows events.
        """

        unique_alerts = []
        seen_events = set()

        for alert in alerts:
            if alert.event_record_id is None:
                unique_alerts.append(alert)
                continue

            event_key = (
                alert.agent_name,
                alert.event_record_id,
            )

            if event_key in seen_events:
                continue

            seen_events.add(event_key)
            unique_alerts.append(alert)

        return unique_alerts
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
        Execute an alert search and normalize the results.
        """

        response = self.indexer.search_alerts(query)

        return [
            Alert.from_api(hit["_source"])
            for hit in response["hits"]["hits"]
        ]
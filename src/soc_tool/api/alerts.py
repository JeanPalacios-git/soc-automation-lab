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
        """
        Create a new alert service.
        """

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

        response = self.indexer.search_alerts(query)

        hits = response["hits"]["hits"]

        return [
            Alert.from_api(hit["_source"])
            for hit in hits
        ]
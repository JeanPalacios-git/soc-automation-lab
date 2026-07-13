"""
Wazuh Indexer client.

Provides a client for querying alerts stored in the Wazuh Indexer.
"""

import requests

from soc_tool.config.settings import settings


class WazuhIndexer:
    """
    Client used to interact with the Wazuh Indexer.
    """

    def __init__(self) -> None:
        """
        Create a new Wazuh Indexer client.
        """

        self.base_url = (
            f"{settings.indexer_host}:{settings.indexer_port}"
        )

        self.session = requests.Session()

        self.session.auth = (
            settings.indexer_username,
            settings.indexer_password,
        )

        self.session.headers.update(
            {
                "Content-Type": "application/json",
            }
        )

    def search_alerts(self, query: dict) -> dict:
        """
        Search alerts stored in the Wazuh Indexer.
        """

        response = self.session.post(
            url=f"{self.base_url}/wazuh-alerts-*/_search",
            json=query,
            verify=settings.verify_ssl,
            timeout=settings.timeout,
        )

        response.raise_for_status()

        return response.json()
"""
Wazuh API client.

Provides a client for interacting with the Wazuh REST API.
"""

import requests

from soc_tool.api.auth import authenticate
from soc_tool.config.settings import settings
from soc_tool.models.alert import Alert


class WazuhClient:
    """
    Client used to communicate with the Wazuh REST API.
    """

    def __init__(self) -> None:
        """
        Create a new authenticated Wazuh client.
        """

        # Authenticate and obtain a JWT token
        self.token = authenticate()

        # Create a reusable HTTP session
        self.session = requests.Session()

        # Configure default headers
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        )

        # Base URL for all API requests
        self.base_url = f"{settings.host}:{settings.port}"

    def get(self, endpoint: str, params: dict | None = None) -> dict:
        """
        Execute a GET request against the Wazuh API.
        """

        response = self.session.get(
            url=f"{self.base_url}{endpoint}",
            params=params,
            verify=settings.verify_ssl,
            timeout=settings.timeout,
        )

        response.raise_for_status()

        return response.json()

    def get_manager_info(self) -> dict:
        """
        Retrieve basic information about the Wazuh manager.
        """

        return self.get("/manager/info")

    def get_alerts(self, limit: int = 100) -> list[Alert]:
        """
        Retrieve the latest alerts from Wazuh.
        """

        response = self.get(
            "/alerts",
            params={"limit": limit},
        )

        alerts = response["data"]["affected_items"]

        return [
            Alert.from_api(alert)
            for alert in alerts
        ]
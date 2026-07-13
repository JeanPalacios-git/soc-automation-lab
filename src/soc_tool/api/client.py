"""
Wazuh API client.

Provides a client for interacting with the Wazuh REST API.
"""

import requests

from soc_tool.api.auth import authenticate
from soc_tool.config.settings import settings


class WazuhClient:
    """
    Client used to communicate with the Wazuh REST API.
    """

    def __init__(self) -> None:
        """
        Create a new authenticated Wazuh client.
        """

        self.token = authenticate()

        self.session = requests.Session()

        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        )

        self.base_url = f"{settings.host}:{settings.port}"

    def get(self, endpoint: str, params: dict | None = None) -> dict:
        """
        Execute a GET request.
        """

        response = self.session.get(
            url=f"{self.base_url}{endpoint}",
            params=params,
            verify=settings.verify_ssl,
            timeout=settings.timeout,
        )

        response.raise_for_status()

        return response.json()

    def post(self, endpoint: str, json: dict | None = None) -> dict:
        """
        Execute a POST request.
        """

        response = self.session.post(
            url=f"{self.base_url}{endpoint}",
            json=json,
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
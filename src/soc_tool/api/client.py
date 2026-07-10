"""
Wazuh API client.

Provides a client for interacting with the Wazuh REST API.
"""

from soc_tool.api.auth import authenticate


class WazuhClient:
    """
    Client used to communicate with the Wazuh REST API.
    """

    def __init__(self) -> None:
        """
        Create a new authenticated Wazuh client.
        """

        self.token = authenticate()
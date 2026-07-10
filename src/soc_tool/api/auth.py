"""
Authentication utilities for the Wazuh API.
"""

import requests
import urllib3

from requests.auth import HTTPBasicAuth

from soc_tool.config.settings import settings


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def authenticate() -> str:
    """
    Authenticate to the Wazuh API and return a JWT token.
    """

    url = f"{settings.host}:{settings.port}/security/user/authenticate"

    response = requests.get(
        url=url,
        auth=HTTPBasicAuth(
            settings.username,
            settings.password,
        ),
        verify=settings.verify_ssl,
        timeout=settings.timeout,
    )


    response.raise_for_status()

    token = response.json()["data"]["token"]

    return token
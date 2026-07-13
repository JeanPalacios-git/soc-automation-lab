"""
Tests for Wazuh API authentication.
"""

from soc_tool.api.auth import authenticate


def test_authenticate_returns_jwt() -> None:
    token = authenticate()

    assert isinstance(token, str)
    assert token
    assert token.startswith("eyJ")
"""
Tests for application settings.
"""

from soc_tool.config.settings import settings


def test_wazuh_api_settings() -> None:
    assert settings.host
    assert settings.port == 55000
    assert settings.username
    assert settings.password


def test_wazuh_indexer_settings() -> None:
    assert settings.indexer_host
    assert settings.indexer_port == 9200
    assert settings.indexer_username
    assert settings.indexer_password


def test_http_settings() -> None:
    assert isinstance(settings.verify_ssl, bool)
    assert settings.timeout > 0
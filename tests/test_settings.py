"""
Tests for application settings.
"""

import importlib

import soc_tool.config.settings as settings_module


def test_wazuh_api_settings(monkeypatch) -> None:
    with monkeypatch.context() as patch:
        patch.setenv("WAZUH_HOST", "https://127.0.0.1")
        patch.setenv("WAZUH_PORT", "55000")
        patch.setenv("WAZUH_USERNAME", "test-user")
        patch.setenv("WAZUH_PASSWORD", "test-password")

        module = importlib.reload(settings_module)

        assert module.settings.host == "https://127.0.0.1"
        assert module.settings.port == 55000
        assert module.settings.username == "test-user"
        assert module.settings.password == "test-password"

    importlib.reload(settings_module)


def test_wazuh_indexer_settings(monkeypatch) -> None:
    with monkeypatch.context() as patch:
        patch.setenv(
            "WAZUH_INDEXER_HOST",
            "https://127.0.0.1",
        )
        patch.setenv("WAZUH_INDEXER_PORT", "9200")
        patch.setenv("WAZUH_INDEXER_USERNAME", "test-user")
        patch.setenv(
            "WAZUH_INDEXER_PASSWORD",
            "test-password",
        )

        module = importlib.reload(settings_module)

        assert module.settings.indexer_host == "https://127.0.0.1"
        assert module.settings.indexer_port == 9200
        assert module.settings.indexer_username == "test-user"
        assert module.settings.indexer_password == "test-password"

    importlib.reload(settings_module)


def test_http_settings(monkeypatch) -> None:
    with monkeypatch.context() as patch:
        patch.setenv("VERIFY_SSL", "true")
        patch.setenv("REQUEST_TIMEOUT", "45")

        module = importlib.reload(settings_module)

        assert module.settings.verify_ssl is True
        assert module.settings.timeout == 45

    importlib.reload(settings_module)

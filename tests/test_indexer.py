import pytest

pytestmark = pytest.mark.integration

"""
Tests for the Wazuh Indexer client.
"""

from soc_tool.api.indexer import WazuhIndexer


def test_search_alerts() -> None:
    indexer = WazuhIndexer()

    response = indexer.search_alerts(
        {
            "size": 1,
        }
    )

    assert "hits" in response
    assert "hits" in response["hits"]
    assert len(response["hits"]["hits"]) == 1

    alert = response["hits"]["hits"][0]

    assert "_source" in alert
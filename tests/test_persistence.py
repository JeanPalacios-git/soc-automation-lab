"""
Tests for finding persistence and investigation state.
"""

from soc_tool.detections.persistence import FindingStore
from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


def create_finding() -> Finding:
    alert = Alert(
        timestamp="2026-07-13T10:00:00.000+0000",
        agent_name="JeanPc",
        rule_id="91802",
        rule_level=12,
        event_id="4104",
        username=None,
        source_ip=None,
        script_block_text="IEX DownloadString",
        subject_username=None,
        target_domain=None,
        member_name=None,
        event_record_id="5000",
        raw_data={},
    )

    return Finding(
        title="Suspicious PowerShell",
        severity="HIGH",
        mitre_id="T1059.001",
        description="Suspicious PowerShell activity detected.",
        recommendation="Investigate the PowerShell script.",
        evidence={
            "matched_patterns": [
                "downloadstring",
                "iex",
            ],
        },
        related_alerts=[alert],
    )


def test_finding_fingerprint_is_deterministic() -> None:
    first_finding = create_finding()
    second_finding = create_finding()

    assert first_finding.fingerprint == second_finding.fingerprint


def test_store_creates_open_finding(tmp_path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    finding = create_finding()

    store.sync([finding])

    assert store.get_status(finding.fingerprint) == "OPEN"


def test_store_preserves_resolved_status(tmp_path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    finding = create_finding()

    store.sync([finding])

    store.set_status(
        finding.fingerprint,
        "RESOLVED",
        "Controlled SOC lab activity.",
    )

    store.sync([finding])

    assert store.get_status(finding.fingerprint) == "RESOLVED"


def test_store_filters_closed_findings(tmp_path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    finding = create_finding()

    store.sync([finding])

    store.set_status(
        finding.fingerprint,
        "FALSE_POSITIVE",
        "Authorized PowerShell test.",
    )

    open_findings = store.get_open_findings([finding])

    assert open_findings == []


def test_store_rejects_invalid_status(tmp_path) -> None:
    store = FindingStore(tmp_path / "findings.db")
    finding = create_finding()

    store.sync([finding])

    try:
        store.set_status(
            finding.fingerprint,
            "POTATO",
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Expected ValueError for invalid status"
        )

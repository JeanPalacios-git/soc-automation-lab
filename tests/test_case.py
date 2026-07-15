from soc_tool.models.case import Case
from soc_tool.models.finding import Finding


def test_case_groups_findings():
    finding = Finding(
        title="Test Finding",
        description="Test security finding",
        severity="High",
        mitre_id="T0000",
        recommendation="Investigate the activity",
        evidence={"test": "evidence"},
        related_alerts=[],
    )

    case = Case(
    case_id="CASE-001",
    title="Test Security Case",
    severity="High",
    findings=[finding],
)
    assert case.title == "Test Security Case"
    assert case.severity == "High"
    assert case.findings == [finding]
    assert case.status == "Open"
"""
Tests for the detection analysis engine.
"""

from soc_tool.detections.engine import AnalysisEngine
from soc_tool.models.finding import Finding


def create_finding(title: str) -> Finding:
    return Finding(
        title=title,
        severity="HIGH",
        mitre_id="T0000",
        description="Test finding.",
        recommendation="Test recommendation.",
        evidence={},
        related_alerts=[],
    )


class FakeDetector:
    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings

    def detect(self, alerts: list) -> list[Finding]:
        return self.findings


def test_engine_combines_detector_findings() -> None:
    engine = AnalysisEngine(
        detectors=[
            FakeDetector([
                create_finding("Detection One"),
            ]),
            FakeDetector([
                create_finding("Detection Two"),
            ]),
        ]
    )

    findings = engine.analyze([])

    assert len(findings) == 2
    assert findings[0].title == "Detection One"
    assert findings[1].title == "Detection Two"


def test_engine_returns_empty_list_without_findings() -> None:
    engine = AnalysisEngine(
        detectors=[
            FakeDetector([]),
            FakeDetector([]),
        ]
    )

    findings = engine.analyze([])

    assert findings == []

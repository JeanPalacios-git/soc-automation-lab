"""
Tests for the detection analysis engine.
"""

from soc_tool.detections.engine import AnalysisEngine


class FakeDetector:
    def __init__(self, findings: list[dict]) -> None:
        self.findings = findings

    def detect(self, alerts: list) -> list[dict]:
        return self.findings


def test_engine_combines_detector_findings() -> None:
    engine = AnalysisEngine(
        detectors=[
            FakeDetector(
                [{"detection": "Detection One"}]
            ),
            FakeDetector(
                [{"detection": "Detection Two"}]
            ),
        ]
    )

    findings = engine.analyze([])

    assert len(findings) == 2
    assert findings[0]["detection"] == "Detection One"
    assert findings[1]["detection"] == "Detection Two"


def test_engine_returns_empty_list_without_findings() -> None:
    engine = AnalysisEngine(
        detectors=[
            FakeDetector([]),
            FakeDetector([]),
        ]
    )

    findings = engine.analyze([])

    assert findings == []
"""
Detection analysis engine.

Coordinates multiple detectors against normalized Wazuh alerts.
"""

from soc_tool.models.alert import Alert


class AnalysisEngine:
    """Run multiple detection modules against a collection of alerts."""

    def __init__(self, detectors: list) -> None:
        self.detectors = detectors

    def analyze(self, alerts: list[Alert]) -> list[dict]:
        """Run all configured detectors and combine their findings."""

        findings = []

        for detector in self.detectors:
            detector_findings = detector.detect(alerts)
            findings.extend(detector_findings)

        return findings
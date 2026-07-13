"""
Tests for SOC analysis reporting.
"""

from pathlib import Path

from soc_tool.models.finding import Finding
from soc_tool.models.report import Report
from soc_tool.reports.generator import ReportGenerator


def create_finding(
    title: str,
    severity: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_id="T0000",
        description="Test finding description.",
        recommendation="Test recommendation.",
        evidence={
            "username": "soctest",
        },
        related_alerts=[],
    )


def test_report_calculates_finding_counts() -> None:
    report = Report(
        title="SOC Analysis Report",
        generated_at="2026-07-13T10:00:00",
        findings=[
            create_finding("Detection One", "HIGH"),
            create_finding("Detection Two", "HIGH"),
            create_finding("Detection Three", "MEDIUM"),
        ],
    )

    assert report.total_findings == 3
    assert report.high_findings == 2
    assert report.medium_findings == 1


def test_generate_html_report(tmp_path: Path) -> None:
    report = Report(
        title="SOC Analysis Report",
        generated_at="2026-07-13T10:00:00",
        findings=[
            create_finding("Possible Brute Force", "HIGH"),
        ],
    )

    output_path = tmp_path / "report.html"

    generator = ReportGenerator()
    generator.generate_html(report, output_path)

    content = output_path.read_text(encoding="utf-8")

    assert output_path.exists()
    assert "SOC Analysis Report" in content
    assert "Possible Brute Force" in content
    assert "HIGH" in content
    assert "soctest" in content
    
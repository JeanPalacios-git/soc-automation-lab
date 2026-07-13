"""
Tests for SOC analysis reporting.
"""

from pathlib import Path

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding
from soc_tool.models.report import Report
from soc_tool.reports.generator import ReportGenerator


def create_alert() -> Alert:
    return Alert(
        timestamp="2026-07-13T10:00:00.000+0000",
        agent_name="DC01",
        rule_id="60122",
        rule_level=5,
        event_id="4625",
        username="soctest",
        source_ip="127.0.0.1",
        script_block_text=None,
        subject_username=None,
        target_domain="SOCLAB",
        member_name=None,
        event_record_id="1000",
        raw_data={},
    )


def create_finding(
    title: str,
    severity: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_id="T1110",
        description="Test finding description.",
        recommendation="Test recommendation.",
        evidence={
            "username": "soctest",
        },
        related_alerts=[create_alert()],
    )


def test_report_calculates_finding_counts() -> None:
    report = Report(
        title="SOC Analysis Report",
        generated_at="2026-07-13T10:00:00+00:00",
        findings=[
            create_finding("Detection One", "HIGH"),
            create_finding("Detection Two", "HIGH"),
            create_finding("Detection Three", "MEDIUM"),
        ],
    )

    assert report.total_findings == 3
    assert report.high_findings == 2
    assert report.medium_findings == 1
    assert report.affected_agents == ["DC01"]
    assert report.generated_at_display == "2026-07-13 10:00:00 Costa Rica"


def test_generate_html_report(tmp_path: Path) -> None:
    report = Report(
        title="SOC Analysis Report",
        generated_at="2026-07-13T10:00:00+00:00",
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
    assert "Executive Summary" in content
    assert "Possible Brute Force" in content
    assert "HIGH" in content
    assert "DC01" in content
    assert "soctest" in content
    assert "attack.mitre.org/techniques/T1110/" in content


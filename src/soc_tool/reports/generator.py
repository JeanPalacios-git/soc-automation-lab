"""
HTML report generator.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from soc_tool.models.report import Report


class ReportGenerator:
    """Generate HTML reports from SOC analysis results."""

    def __init__(self) -> None:
        template_directory = Path(__file__).parent / "templates"

        self.environment = Environment(
            loader=FileSystemLoader(template_directory),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_html(
        self,
        report: Report,
        output_path: Path,
    ) -> None:
        """Render a SOC analysis report to an HTML file."""

        template = self.environment.get_template("reports.html")

        rendered_report = template.render(report=report)

        output_path.write_text(
            rendered_report,
            encoding="utf-8",
        )

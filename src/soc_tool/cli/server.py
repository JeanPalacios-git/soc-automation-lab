"""
Local analyst triage interface.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs
import subprocess
import sys
import webbrowser

from soc_tool.detections.persistence import FindingStore


DATABASE_PATH = Path("soc_findings.db")
REPORT_PATH = Path("soc_analysis_report.html")


class TriageHandler(BaseHTTPRequestHandler):
    """Serve the SOC report and process analyst actions."""

    def do_GET(self) -> None:
        if self.path != "/":
            self.send_error(404)
            return

        if not REPORT_PATH.exists():
            self.send_error(404, "SOC report not found")
            return

        content = REPORT_PATH.read_bytes()

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()

        self.wfile.write(content)

    def do_POST(self) -> None:
        if self.path != "/finding/update":
            self.send_error(404)
            return

        content_length = int(
            self.headers.get("Content-Length", 0)
        )

        body = self.rfile.read(content_length).decode("utf-8")
        form = parse_qs(body)

        fingerprint = form.get("fingerprint", [None])[0]
        status = form.get("status", [None])[0]
        analyst_note = form.get("analyst_note", [None])[0]

        if not fingerprint or not status:
            self.send_error(400, "Missing finding data")
            return

        store = FindingStore(DATABASE_PATH)

        try:
            store.set_status(
                fingerprint,
                status,
                analyst_note or None,
            )
        except (KeyError, ValueError) as error:
            self.send_error(400, str(error))
            return

        subprocess.run(
            [
                sys.executable,
                "examples/run_analysis.py",
            ],
            check=True,
        )

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def main() -> None:
    address = ("127.0.0.1", 8080)

    server = HTTPServer(
        address,
        TriageHandler,
    )

    url = "http://127.0.0.1:8080"

    print()
    print("SOC Analyst Interface")
    print(f"Running at: {url}")
    print("Press CTRL+C to stop.")
    print()

    webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("SOC Analyst Interface stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

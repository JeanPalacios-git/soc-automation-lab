"""
SQLite persistence for security findings.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from soc_tool.models.finding import Finding


class FindingStore:
    """Persist and manage finding investigation state."""

    VALID_STATUSES = {
        "OPEN",
        "RESOLVED",
        "FALSE_POSITIVE",
    }

    def __init__(self, database_path: Path | str) -> None:
        self.database_path = database_path
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    fingerprint TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    analyst_note TEXT,
                    agent_name TEXT
                )
                """
            )

            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(findings)"
                ).fetchall()
            }

            if "agent_name" not in columns:
                connection.execute(
                    """
                    ALTER TABLE findings
                    ADD COLUMN agent_name TEXT
                    """
                )

    def sync(self, findings: list[Finding]) -> None:
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            for finding in findings:
                agents = sorted(
                    {
                        alert.agent_name
                        for alert in finding.related_alerts
                        if alert.agent_name
                    }
                )

                agent_name = ", ".join(agents) or "Unknown"

                connection.execute(
                    """
                    INSERT INTO findings (
                        fingerprint,
                        title,
                        severity,
                        status,
                        first_seen,
                        last_seen,
                        analyst_note,
                        agent_name
                    )
                    VALUES (?, ?, ?, 'OPEN', ?, ?, NULL, ?)
                    ON CONFLICT(fingerprint)
                    DO UPDATE SET
                        last_seen = excluded.last_seen,
                        agent_name = excluded.agent_name
                    """,
                    (
                        finding.fingerprint,
                        finding.title,
                        finding.severity,
                        now,
                        now,
                        agent_name,
                    ),
                )

    def get_status(self, fingerprint: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT status
                FROM findings
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()

        if row is None:
            return None

        return row["status"]

    def set_status(
        self,
        fingerprint: str,
        status: str,
        analyst_note: str | None = None,
    ) -> None:
        if status not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid finding status: {status}"
            )

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE findings
                SET status = ?,
                    analyst_note = ?
                WHERE fingerprint = ?
                """,
                (
                    status,
                    analyst_note,
                    fingerprint,
                ),
            )

            if cursor.rowcount == 0:
                raise KeyError(
                    f"Finding not found: {fingerprint}"
                )

    def get_open_findings(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        return [
            finding
            for finding in findings
            if self.get_status(finding.fingerprint) == "OPEN"
        ]

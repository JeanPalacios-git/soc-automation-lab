"""
SOC Automation Lab command-line interface.
"""

import argparse
from pathlib import Path

from soc_tool.detections.persistence import FindingStore


DATABASE_PATH = Path("soc_findings.db")


def list_findings(store: FindingStore) -> None:
    with store._connect() as connection:
        rows = connection.execute(
            """
            SELECT
                fingerprint,
                title,
                severity,
                status,
                analyst_note,
                agent_name
            FROM findings
            ORDER BY last_seen DESC
            """
        ).fetchall()

    if not rows:
        print("No findings stored.")
        return

    for row in rows:
        print()
        print(f"ID: {row['fingerprint'][:12]}")
        print(f"Title: {row['title']}")
        print(f"Agent: {row['agent_name'] or 'Unknown'}")
        print(f"Severity: {row['severity']}")
        print(f"Status: {row['status']}")

        if row["analyst_note"]:
            print(f"Note: {row['analyst_note']}")


def update_status(
    store: FindingStore,
    fingerprint_prefix: str,
    status: str,
    note: str | None,
) -> None:
    with store._connect() as connection:
        rows = connection.execute(
            """
            SELECT fingerprint
            FROM findings
            WHERE fingerprint LIKE ?
            """,
            (f"{fingerprint_prefix}%",),
        ).fetchall()

    if not rows:
        raise SystemExit(
            f"Finding not found: {fingerprint_prefix}"
        )

    if len(rows) > 1:
        raise SystemExit(
            f"Finding ID is ambiguous: {fingerprint_prefix}"
        )

    fingerprint = rows[0]["fingerprint"]

    store.set_status(
        fingerprint,
        status,
        note,
    )

    print(
        f"Finding {fingerprint[:12]} marked as {status}."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Automation Lab CLI"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser("list")

    resolve_parser = subparsers.add_parser("resolve")
    resolve_parser.add_argument("finding_id")
    resolve_parser.add_argument("--note")

    false_positive_parser = subparsers.add_parser(
        "false-positive"
    )
    false_positive_parser.add_argument("finding_id")
    false_positive_parser.add_argument("--note")

    args = parser.parse_args()

    store = FindingStore(DATABASE_PATH)

    if args.command == "list":
        list_findings(store)

    elif args.command == "resolve":
        update_status(
            store,
            args.finding_id,
            "RESOLVED",
            args.note,
        )

    elif args.command == "false-positive":
        update_status(
            store,
            args.finding_id,
            "FALSE_POSITIVE",
            args.note,
        )


if __name__ == "__main__":
    main()

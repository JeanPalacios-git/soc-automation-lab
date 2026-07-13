"""
Brute force detection logic.
"""

from collections import defaultdict
from datetime import datetime, timedelta

from soc_tool.models.alert import Alert


class BruteForceDetector:
    """
    Detects repeated failed Windows logon attempts.
    """

    def __init__(
        self,
        threshold: int = 5,
        window_minutes: int = 5,
    ) -> None:
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def detect(self, alerts: list[Alert]) -> list[dict]:
        """
        Detect repeated failed logons within a time window.
        """

        failed_logons: dict[
            tuple[str, str],
            list[Alert],
        ] = defaultdict(list)

        for alert in alerts:
            if alert.event_id != "4625":
                continue

            source_ip = alert.source_ip or "Unknown"
            username = alert.username or "Unknown"

            key = (source_ip, username)

            failed_logons[key].append(alert)

        findings = []

        for (source_ip, username), matched_alerts in failed_logons.items():
            sorted_alerts = sorted(
                matched_alerts,
                key=lambda alert: self._parse_timestamp(alert.timestamp),
            )

            for start_index, start_alert in enumerate(sorted_alerts):
                window_alerts = []

                start_time = self._parse_timestamp(
                    start_alert.timestamp
                )

                for alert in sorted_alerts[start_index:]:
                    alert_time = self._parse_timestamp(
                        alert.timestamp
                    )

                    if alert_time - start_time > self.window:
                        break

                    window_alerts.append(alert)

                if len(window_alerts) >= self.threshold:
                    findings.append(
                        {
                            "detection": "Possible Brute Force",
                            "source_ip": source_ip,
                            "username": username,
                            "failed_attempts": len(window_alerts),
                            "first_seen": window_alerts[0].timestamp,
                            "last_seen": window_alerts[-1].timestamp,
                        }
                    )

                    break

        return findings

    @staticmethod
    def _parse_timestamp(timestamp: str) -> datetime:
        """
        Convert a Wazuh timestamp into a datetime object.
        """

        return datetime.strptime(
            timestamp,
            "%Y-%m-%dT%H:%M:%S.%f%z",
        )
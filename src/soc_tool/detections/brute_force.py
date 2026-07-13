"""
Brute force detection logic.
"""

from collections import defaultdict
from datetime import datetime, timedelta

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class BruteForceDetector:
    """
    Detect repeated failed logon attempts within a time window.
    """

    FAILED_LOGON_EVENT_ID = "4625"
    ATTEMPT_THRESHOLD = 5
    TIME_WINDOW = timedelta(minutes=5)

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect independent brute force campaigns.
        """

        grouped_alerts = defaultdict(list)

        for alert in alerts:
            if alert.event_id != self.FAILED_LOGON_EVENT_ID:
                continue

            if not alert.source_ip or not alert.username:
                continue

            key = (
                alert.source_ip,
                alert.username,
            )

            grouped_alerts[key].append(alert)

        findings = []

        for (source_ip, username), group in grouped_alerts.items():
            ordered_alerts = sorted(
                group,
                key=lambda alert: datetime.fromisoformat(
                    alert.timestamp
                ),
            )

            start_index = 0

            while start_index < len(ordered_alerts):
                campaign_start = datetime.fromisoformat(
                    ordered_alerts[start_index].timestamp
                )

                campaign_alerts = []

                for alert in ordered_alerts[start_index:]:
                    alert_time = datetime.fromisoformat(
                        alert.timestamp
                    )

                    if alert_time - campaign_start > self.TIME_WINDOW:
                        break

                    campaign_alerts.append(alert)

                if len(campaign_alerts) >= self.ATTEMPT_THRESHOLD:
                    triggering_alerts = campaign_alerts[
                        : self.ATTEMPT_THRESHOLD
                    ]

                    first_seen = triggering_alerts[0].timestamp
                    last_seen = triggering_alerts[-1].timestamp

                    findings.append(
                        Finding(
                            title="Possible Brute Force",
                            severity="HIGH",
                            mitre_id="T1110",
                            description=(
                                "Multiple failed logon attempts were "
                                "detected within a short time window."
                            ),
                            recommendation=(
                                "Investigate the source IP and target "
                                "account for possible brute force activity."
                            ),
                            evidence={
                                "source_ip": source_ip,
                                "username": username,
                                "failed_attempts": len(triggering_alerts),
                                "first_seen": first_seen,
                                "last_seen": last_seen,
                            },
                            related_alerts=triggering_alerts,
                        )
                    )

                    start_index += len(campaign_alerts)
                    continue

                start_index += 1

        return findings

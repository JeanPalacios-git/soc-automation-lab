"""
Detect additions to privileged Active Directory groups.
"""

from soc_tool.models.alert import Alert


class GroupMembershipDetector:
    """Detect users added to privileged Active Directory groups."""

    PRIVILEGED_GROUPS = {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
    }

    def detect(self, alerts: list[Alert]) -> list[dict]:
        findings = []

        for alert in alerts:
            if alert.event_id != "4728":
                continue

            group_name = alert.username

            if not group_name:
                continue

            if group_name.lower() not in self.PRIVILEGED_GROUPS:
                continue

            findings.append(
                {
                    "detection": "Privileged Group Membership Changed",
                    "agent_name": alert.agent_name,
                    "group_name": group_name,
                    "member_name": alert.member_name,
                    "changed_by": alert.subject_username,
                    "target_domain": alert.target_domain,
                    "timestamp": alert.timestamp,
                }
            )

        return findings

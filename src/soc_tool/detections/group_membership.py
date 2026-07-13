"""
Detect additions to privileged Active Directory groups.
"""

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class GroupMembershipDetector:
    """Detect users added to privileged Active Directory groups."""

    PRIVILEGED_GROUPS = {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
    }

    def detect(self, alerts: list[Alert]) -> list[Finding]:
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
                Finding(
                    title="Privileged Group Membership Changed",
                    severity="HIGH",
                    mitre_id="T1098.007",
                    description=(
                        "A user was added to a privileged Active "
                        "Directory group."
                    ),
                    recommendation=(
                        "Verify that the group membership change was "
                        "authorized and investigate possible privilege escalation."
                    ),
                    evidence={
                        "group_name": group_name,
                        "member_name": alert.member_name,
                        "changed_by": alert.subject_username,
                        "target_domain": alert.target_domain,
                    },
                    related_alerts=[alert],
                )
            )

        return findings

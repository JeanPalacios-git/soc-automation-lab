"""
Linux privileged group membership detection logic.
"""

from typing import Any

from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


class LinuxPrivilegedGroupDetector:
    """
    Detect successful usermod additions to the sudo group.
    """

    RULE_ID = "80792"
    PRIVILEGED_GROUP = "sudo"

    @staticmethod
    def _nested(
        data: dict[str, Any],
        *keys: str,
    ) -> Any:
        """
        Safely retrieve a nested value.
        """

        current: Any = data

        for key in keys:
            if not isinstance(current, dict):
                return None

            current = current.get(key)

        return current

    def detect(self, alerts: list[Alert]) -> list[Finding]:
        """
        Detect successful additions to the Linux sudo group.
        """

        findings = []

        for alert in alerts:
            if alert.rule_id != self.RULE_ID:
                continue

            data = alert.raw_data.get("data") or {}
            audit = data.get("audit") or {}
            execve = audit.get("execve") or {}

            command = (
                audit.get("command")
                or data.get("audit.command")
            )

            executable = (
                audit.get("exe")
                or data.get("audit.exe")
            )

            argument_1 = (
                execve.get("a1")
                or data.get("audit.execve.a1")
            )

            argument_2 = (
                execve.get("a2")
                or data.get("audit.execve.a2")
            )

            target_user = (
                execve.get("a3")
                or data.get("audit.execve.a3")
            )

            success = (
                audit.get("success")
                or data.get("audit.success")
            )

            is_usermod = (
                command == "usermod"
                or executable == "/usr/sbin/usermod"
            )

            is_group_append = argument_1 == "-aG"

            is_privileged_group = (
                argument_2 == self.PRIVILEGED_GROUP
            )

            is_successful = str(success).lower() == "yes"

            if not (
                is_usermod
                and is_group_append
                and is_privileged_group
                and is_successful
            ):
                continue

            findings.append(
                Finding(
                    title=(
                        "Linux Privileged Group Membership Changed"
                    ),
                    severity="HIGH",
                    mitre_id="T1098.007",
                    description=(
                        "A Linux user was successfully added to the "
                        "sudo privileged group."
                    ),
                    recommendation=(
                        "Validate the privilege assignment and "
                        "confirm that the target user requires sudo "
                        "access. Review related administrative "
                        "activity."
                    ),
                    evidence={
                        "target_user": target_user or "Unknown",
                        "privileged_group": argument_2,
                        "command": command or executable,
                        "operation": argument_1,
                        "success": success,
                    },
                    related_alerts=[alert],
                )
            )

        return findings

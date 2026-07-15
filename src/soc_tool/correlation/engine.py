"""
Correlation engine for grouping related security findings.
"""

from datetime import datetime

from soc_tool.models.case import Case
from soc_tool.models.finding import Finding


class CorrelationEngine:
    """
    Groups related security findings into investigation cases.
    """

    def __init__(self, correlation_window_hours: int = 24):
        """
        Initialize the correlation engine.

        Args:
            correlation_window_hours:
                Maximum time difference allowed between related findings.
        """

        self.correlation_window_hours = correlation_window_hours

    @staticmethod
    def _normalize_identity(identity: str | None) -> str:
        """
        Normalize a user identity for correlation.

        Supports plain usernames and Active Directory
        distinguished names.
        """

        if not identity:
            return ""

        identity = identity.strip()

        if identity.upper().startswith("CN="):
            identity = identity.split(",", 1)[0]
            identity = identity[3:]

        return identity.casefold()

    @staticmethod
    def _get_finding_timestamp(finding: Finding) -> datetime | None:
        """
        Get the earliest available timestamp from a finding's related alerts.
        """

        timestamps = []

        for alert in finding.related_alerts:
            if not alert.timestamp:
                continue

            try:
                timestamp = datetime.fromisoformat(
                    alert.timestamp.replace("Z", "+00:00")
                )
                timestamps.append(timestamp)
            except ValueError:
                continue

        if not timestamps:
            return None

        return min(timestamps)

    @staticmethod
    def _get_finding_host(finding: Finding) -> str:
        """
        Get the host associated with a finding.
        """

        for alert in finding.related_alerts:
            if alert.agent_name:
                return alert.agent_name.strip().casefold()

        return ""

    def _is_ordered_within_time_window(
        self,
        first_finding: Finding,
        second_finding: Finding,
    ) -> bool:
        """
        Check whether the second finding occurred after the first
        and within the configured correlation window.
        """

        first_timestamp = self._get_finding_timestamp(
            first_finding
        )
        second_timestamp = self._get_finding_timestamp(
            second_finding
        )

        if first_timestamp is None or second_timestamp is None:
            return False

        difference = (
            second_timestamp - first_timestamp
        ).total_seconds()

        maximum_difference = (
            self.correlation_window_hours * 3600
        )

        return (
            0 <= difference <= maximum_difference
        )
    def _within_time_window(
        self,
        first_finding: Finding,
        second_finding: Finding,
    ) -> bool:
        """
        Check whether two findings occurred within the configured time window.
        """

        first_timestamp = self._get_finding_timestamp(first_finding)
        second_timestamp = self._get_finding_timestamp(second_finding)

        if first_timestamp is None or second_timestamp is None:
            return True

        difference = abs(
            (second_timestamp - first_timestamp).total_seconds()
        )

        maximum_difference = self.correlation_window_hours * 3600

        return difference <= maximum_difference

    @staticmethod
    def _build_timeline(findings: list[Finding]) -> list[dict]:
        """
        Build a chronological timeline from finding alerts.
        """

        timeline = []

        for finding in findings:
            for alert in finding.related_alerts:
                if not alert.timestamp:
                    continue

                try:
                    parsed_timestamp = datetime.fromisoformat(
                        alert.timestamp.replace("Z", "+00:00")
                    )
                except ValueError:
                    continue

                timeline.append(
                    {
                        "timestamp": alert.timestamp,
                        "event": finding.title,
                        "_sort_time": parsed_timestamp,
                    }
                )

        timeline.sort(
            key=lambda item: item["_sort_time"]
        )

        for item in timeline:
            item.pop("_sort_time")

        return timeline

    @staticmethod
    def _build_windows_entities(
        account_creation: Finding,
        group_change: Finding,
    ) -> dict:
        """
        Build important entities for a Windows privileged account case.
        """

        return {
            "user": account_creation.evidence.get("created_user"),
            "group": group_change.evidence.get("group_name"),
            "domain": (
                account_creation.evidence.get("target_domain")
                or group_change.evidence.get("target_domain")
            ),
        }

    @staticmethod
    def _build_linux_entities(
        user_creation: Finding,
        group_change: Finding,
    ) -> dict:
        """
        Build important entities for a Linux privileged account case.
        """

        host = None

        for alert in user_creation.related_alerts:
            if alert.agent_name:
                host = alert.agent_name
                break

        if host is None:
            for alert in group_change.related_alerts:
                if alert.agent_name:
                    host = alert.agent_name
                    break

        return {
            "user": user_creation.evidence.get("username"),
            "group": group_change.evidence.get("privileged_group"),
            "host": host,
        }


    @staticmethod
    def _merge_case_findings(
        case: Case,
        findings: list[Finding],
    ) -> None:
        """
        Enrich an existing case with additional findings.
        """

        for finding in findings:
            if finding not in case.findings:
                case.findings.append(finding)

        case.timeline = CorrelationEngine._build_timeline(
            case.findings
        )

        if len(case.findings) >= 3:
            case.title = (
                "Potential Multi-Stage Activity"
            )


    def _find_enrichment_case(
        self,
        cases: list[Case],
        finding: Finding,
    ) -> Case | None:
        """
        Find an existing case that belongs to same investigation.
        """

        host = self._get_finding_host(finding)

        for case in cases:
            case_hosts = {
                self._get_finding_host(item)
                for item in case.findings
            }

            if host and host in case_hosts:
                return case

        return None

    def correlate(self, findings: list[Finding]) -> list[Case]:
        """
        Correlate findings and return investigation cases.
        """

        cases = []
        case_number = 1

        windows_account_creations = [
            finding
            for finding in findings
            if finding.title == "User Account Created"
        ]

        windows_group_changes = [
            finding
            for finding in findings
            if finding.title == "Privileged Group Membership Changed"
        ]

        for account_creation in windows_account_creations:
            created_user = self._normalize_identity(
                account_creation.evidence.get("created_user")
            )

            for group_change in windows_group_changes:
                added_member = self._normalize_identity(
                    group_change.evidence.get("member_name")
                )

                same_identity = (
                    created_user
                    and created_user == added_member
                )

                within_time_window = self._within_time_window(
                    account_creation,
                    group_change,
                )

                if same_identity and within_time_window:
                    correlated_findings = [
                        account_creation,
                        group_change,
                    ]

                    case = Case(
                        case_id=f"CASE-{case_number:03d}",
                        title="Potential Privileged Account Activity",
                        severity="High",
                        findings=correlated_findings,
                        timeline=self._build_timeline(
                            correlated_findings
                        ),
                        entities=self._build_windows_entities(
                            account_creation,
                            group_change,
                        ),
                    )

                    cases.append(case)
                    case_number += 1

        linux_user_creations = [
            finding
            for finding in findings
            if finding.title == "Linux User Account Created"
        ]

        linux_group_changes = [
            finding
            for finding in findings
            if finding.title
            == "Linux Privileged Group Membership Changed"
        ]

        for user_creation in linux_user_creations:
            created_user = self._normalize_identity(
                user_creation.evidence.get("username")
            )

            creation_host = self._get_finding_host(
                user_creation
            )

            for group_change in linux_group_changes:
                added_user = self._normalize_identity(
                    group_change.evidence.get("target_user")
                )

                group_change_host = self._get_finding_host(
                    group_change
                )

                same_identity = (
                    created_user
                    and created_user == added_user
                )

                same_host = (
                    creation_host
                    and creation_host == group_change_host
                )

                within_time_window = self._within_time_window(
                    user_creation,
                    group_change,
                )

                if (
                    same_identity
                    and same_host
                    and within_time_window
                ):
                    correlated_findings = [
                        user_creation,
                        group_change,
                    ]

                    case = Case(
                        case_id=f"CASE-{case_number:03d}",
                        title=(
                            "Potential Privileged Linux "
                            "Account Activity"
                        ),
                        severity="High",
                        findings=correlated_findings,
                        timeline=self._build_timeline(
                            correlated_findings
                        ),
                        entities=self._build_linux_entities(
                            user_creation,
                            group_change,
                        ),
                    )

                    cases.append(case)
                    case_number += 1

        brute_force_findings = [
            finding
            for finding in findings
            if finding.title == "Possible Brute Force"
        ]

        suspicious_powershell_findings = [
            finding
            for finding in findings
            if finding.title == "Suspicious PowerShell"
        ]

        for brute_force in brute_force_findings:
            brute_force_host = self._get_finding_host(
                brute_force
            )

            for suspicious_powershell in (
                suspicious_powershell_findings
            ):
                powershell_host = self._get_finding_host(
                    suspicious_powershell
                )

                same_host = (
                    brute_force_host
                    and brute_force_host == powershell_host
                )

                ordered_within_time_window = (
                    self._is_ordered_within_time_window(
                        brute_force,
                        suspicious_powershell,
                    )
                )

                if (
                    same_host
                    and ordered_within_time_window
                ):
                    correlated_findings = [
                        brute_force,
                        suspicious_powershell,
                    ]

                    host = None

                    for alert in brute_force.related_alerts:
                        if alert.agent_name:
                            host = alert.agent_name
                            break

                    if host is None:
                        for alert in (
                            suspicious_powershell.related_alerts
                        ):
                            if alert.agent_name:
                                host = alert.agent_name
                                break

                    case = Case(
                        case_id=f"CASE-{case_number:03d}",
                        title=(
                            "Potential Post-Compromise "
                            "PowerShell Activity"
                        ),
                        severity="Critical",
                        findings=correlated_findings,
                        timeline=self._build_timeline(
                            correlated_findings
                        ),
                        entities={
                            "host": host,
                            "target_user": (
                                brute_force.evidence.get(
                                    "username"
                                )
                            ),
                            "source_ip": (
                                brute_force.evidence.get(
                                    "source_ip"
                                )
                            ),
                        },
                    )

                    cases.append(case)
                    case_number += 1


        linux_ssh_brute_force_findings = [
            finding
            for finding in findings
            if finding.title == "Linux SSH Brute Force"
        ]

        linux_failed_sudo_findings = [
            finding
            for finding in findings
            if finding.title == "Linux Failed Sudo Activity"
        ]

        linux_hosts = {
            self._get_finding_host(finding)
            for finding in linux_ssh_brute_force_findings
            if self._get_finding_host(finding)
        }

        for host in linux_hosts:
            host_ssh_findings = [
                finding
                for finding in linux_ssh_brute_force_findings
                if self._get_finding_host(finding) == host
            ]

            host_sudo_findings = [
                finding
                for finding in linux_failed_sudo_findings
                if self._get_finding_host(finding) == host
            ]

            correlated_ssh_findings = []
            correlated_sudo_findings = []

            for ssh_brute_force in host_ssh_findings:
                for failed_sudo in host_sudo_findings:
                    if self._is_ordered_within_time_window(
                        ssh_brute_force,
                        failed_sudo,
                    ):
                        if (
                            ssh_brute_force
                            not in correlated_ssh_findings
                        ):
                            correlated_ssh_findings.append(
                                ssh_brute_force
                            )

                        if (
                            failed_sudo
                            not in correlated_sudo_findings
                        ):
                            correlated_sudo_findings.append(
                                failed_sudo
                            )

            if (
                not correlated_ssh_findings
                or not correlated_sudo_findings
            ):
                continue

            correlated_findings = (
                correlated_ssh_findings
                + correlated_sudo_findings
            )

            first_ssh = correlated_ssh_findings[0]
            first_sudo = correlated_sudo_findings[0]

            case = Case(
                case_id=f"CASE-{case_number:03d}",
                title=(
                    "Potential Linux Post-Compromise "
                    "Privilege Escalation"
                ),
                severity="Critical",
                findings=correlated_findings,
                timeline=self._build_timeline(
                    correlated_findings
                ),
                entities={
                    "host": host,
                    "source_ip": (
                        first_ssh.evidence.get(
                            "source_ip"
                        )
                    ),
                    "source_user": (
                        first_sudo.evidence.get(
                            "source_user"
                        )
                    ),
                    "target_user": (
                        first_sudo.evidence.get(
                            "target_user"
                        )
                    ),
                },
            )

            cases.append(case)
            case_number += 1

        #
        # Pattern #5 - Multi Stage Case Enrichment
        #

        for case in cases:
            existing_findings = case.findings

            for finding in findings:
                if finding in existing_findings:
                    continue

                same_host = (
                    self._get_finding_host(finding)
                    and self._get_finding_host(finding)
                    in {
                        self._get_finding_host(item)
                        for item in existing_findings
                    }
                )

                if same_host:
                    if (
                        finding.title
                        in (
                            "Suspicious PowerShell",
                            "Linux Failed Sudo Activity",
                        )
                    ):
                        self._merge_case_findings(
                            case,
                            [finding],
                        )

        return cases





from soc_tool.correlation.engine import CorrelationEngine
from soc_tool.models.alert import Alert
from soc_tool.models.finding import Finding


def make_alert(
    timestamp: str,
    agent_name: str = "DC01",
) -> Alert:
    return Alert(
        timestamp=timestamp,
        agent_name=agent_name,
        rule_id="test-rule",
        rule_level=10,
        event_id=None,
        username=None,
        source_ip=None,
        event_record_id=None,
        member_name=None,
        script_block_text=None,
        subject_username=None,
        target_domain="SOCLAB",
        raw_data={},
    )


def test_correlation_engine_returns_no_cases_for_no_findings():
    engine = CorrelationEngine()

    cases = engine.correlate([])

    assert cases == []


def test_correlation_engine_returns_no_case_for_single_finding():
    finding = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "SOC Test User"},
        related_alerts=[],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([finding])

    assert cases == []


def test_correlates_account_creation_and_group_membership_for_same_user():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "SOC Test User"},
        related_alerts=[],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "SOC Test User",
            "group_name": "Domain Admins",
        },
        related_alerts=[],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert len(cases) == 1
    assert cases[0].case_id == "CASE-001"
    assert cases[0].title == "Potential Privileged Account Activity"
    assert cases[0].severity == "High"
    assert cases[0].findings == [
        account_creation,
        group_membership,
    ]


def test_does_not_correlate_findings_for_different_users():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "Alice"},
        related_alerts=[],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "Bob",
            "group_name": "Domain Admins",
        },
        related_alerts=[],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert cases == []


def test_correlates_account_creation_with_active_directory_distinguished_name():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "SOC Test User"},
        related_alerts=[],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": (
                "CN=SOC Test User,"
                "OU=Employees,"
                "DC=soclab,"
                "DC=local"
            ),
            "group_name": "GG_IT",
        },
        related_alerts=[],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert len(cases) == 1


def test_creates_multiple_cases_for_multiple_related_users():
    alice_creation = Finding(
        title="User Account Created",
        description="Alice account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "Alice"},
        related_alerts=[],
    )

    alice_group_change = Finding(
        title="Privileged Group Membership Changed",
        description="Alice was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "Alice",
            "group_name": "Domain Admins",
        },
        related_alerts=[],
    )

    bob_creation = Finding(
        title="User Account Created",
        description="Bob account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "Bob"},
        related_alerts=[],
    )

    bob_group_change = Finding(
        title="Privileged Group Membership Changed",
        description="Bob was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "Bob",
            "group_name": "Domain Admins",
        },
        related_alerts=[],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        alice_creation,
        alice_group_change,
        bob_creation,
        bob_group_change,
    ])

    assert len(cases) == 2
    assert cases[0].case_id == "CASE-001"
    assert cases[1].case_id == "CASE-002"


def test_does_not_correlate_findings_with_missing_identity():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={},
        related_alerts=[],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={"group_name": "Domain Admins"},
        related_alerts=[],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert cases == []


def test_correlates_related_findings_within_time_window():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "SOC Test User"},
        related_alerts=[
            make_alert("2026-07-15T10:00:00+00:00")
        ],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "SOC Test User",
            "group_name": "Domain Admins",
        },
        related_alerts=[
            make_alert("2026-07-15T10:05:00+00:00")
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert len(cases) == 1


def test_correlates_related_findings_within_24_hour_window():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "SOC Test User"},
        related_alerts=[
            make_alert("2026-07-15T10:00:00+00:00")
        ],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "SOC Test User",
            "group_name": "Domain Admins",
        },
        related_alerts=[
            make_alert("2026-07-15T15:00:00+00:00")
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert len(cases) == 1


def test_does_not_correlate_findings_outside_24_hour_window():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "SOC Test User"},
        related_alerts=[
            make_alert("2026-07-15T10:00:00+00:00")
        ],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "SOC Test User",
            "group_name": "Domain Admins",
        },
        related_alerts=[
            make_alert("2026-07-17T10:00:00+00:00")
        ],
    )

    engine = CorrelationEngine(
        correlation_window_hours=24
    )

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert cases == []


def test_correlated_case_contains_chronological_timeline():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"created_user": "SOC Test User"},
        related_alerts=[
            make_alert("2026-07-15T10:00:00+00:00")
        ],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": "SOC Test User",
            "group_name": "Domain Admins",
        },
        related_alerts=[
            make_alert("2026-07-15T10:05:00+00:00")
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        group_membership,
        account_creation,
    ])

    assert len(cases) == 1
    assert cases[0].timeline == [
        {
            "timestamp": "2026-07-15T10:00:00+00:00",
            "event": "User Account Created",
        },
        {
            "timestamp": "2026-07-15T10:05:00+00:00",
            "event": "Privileged Group Membership Changed",
        },
    ]


def test_correlated_case_contains_aggregated_entities():
    account_creation = Finding(
        title="User Account Created",
        description="A new user account was created.",
        severity="Medium",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={
            "created_user": "SOC Test User",
            "target_domain": "SOCLAB",
        },
        related_alerts=[],
    )

    group_membership = Finding(
        title="Privileged Group Membership Changed",
        description="A user was added to a privileged group.",
        severity="High",
        mitre_id="T1098",
        recommendation="Verify whether the group membership change was authorized.",
        evidence={
            "member_name": (
                "CN=SOC Test User,"
                "OU=Employees,"
                "DC=soclab,"
                "DC=local"
            ),
            "group_name": "Domain Admins",
            "target_domain": "SOCLAB",
        },
        related_alerts=[],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert len(cases) == 1
    assert cases[0].entities == {
        "user": "SOC Test User",
        "group": "Domain Admins",
        "domain": "SOCLAB",
    }


def test_correlates_linux_user_creation_and_privileged_group_change():
    user_creation = Finding(
        title="Linux User Account Created",
        description="A new Linux user account was created.",
        severity="MEDIUM",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={
            "username": "soc-linux-test",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    privileged_group_change = Finding(
        title="Linux Privileged Group Membership Changed",
        description="A Linux user was added to the sudo group.",
        severity="HIGH",
        mitre_id="T1098.007",
        recommendation="Verify whether the privilege assignment was authorized.",
        evidence={
            "target_user": "soc-linux-test",
            "privileged_group": "sudo",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:05:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        user_creation,
        privileged_group_change,
    ])

    assert len(cases) == 1
    assert cases[0].case_id == "CASE-001"
    assert cases[0].title == (
        "Potential Privileged Linux Account Activity"
    )
    assert cases[0].severity == "High"
    assert cases[0].findings == [
        user_creation,
        privileged_group_change,
    ]
    assert cases[0].entities == {
        "user": "soc-linux-test",
        "group": "sudo",
        "host": "linux-01",
    }


def test_does_not_correlate_linux_findings_for_different_users():
    user_creation = Finding(
        title="Linux User Account Created",
        description="A new Linux user account was created.",
        severity="MEDIUM",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"username": "alice"},
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    privileged_group_change = Finding(
        title="Linux Privileged Group Membership Changed",
        description="A Linux user was added to the sudo group.",
        severity="HIGH",
        mitre_id="T1098.007",
        recommendation="Verify whether the privilege assignment was authorized.",
        evidence={
            "target_user": "bob",
            "privileged_group": "sudo",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:05:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        user_creation,
        privileged_group_change,
    ])

    assert cases == []


def test_does_not_correlate_linux_findings_from_different_hosts():
    user_creation = Finding(
        title="Linux User Account Created",
        description="A new Linux user account was created.",
        severity="MEDIUM",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"username": "soc-linux-test"},
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    privileged_group_change = Finding(
        title="Linux Privileged Group Membership Changed",
        description="A Linux user was added to the sudo group.",
        severity="HIGH",
        mitre_id="T1098.007",
        recommendation="Verify whether the privilege assignment was authorized.",
        evidence={
            "target_user": "soc-linux-test",
            "privileged_group": "sudo",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:05:00+00:00",
                agent_name="linux-02",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        user_creation,
        privileged_group_change,
    ])

    assert cases == []


def test_does_not_correlate_linux_findings_outside_time_window():
    user_creation = Finding(
        title="Linux User Account Created",
        description="A new Linux user account was created.",
        severity="MEDIUM",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"username": "soc-linux-test"},
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    privileged_group_change = Finding(
        title="Linux Privileged Group Membership Changed",
        description="A Linux user was added to the sudo group.",
        severity="HIGH",
        mitre_id="T1098.007",
        recommendation="Verify whether the privilege assignment was authorized.",
        evidence={
            "target_user": "soc-linux-test",
            "privileged_group": "sudo",
        },
        related_alerts=[
            make_alert(
                "2026-07-17T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine(
        correlation_window_hours=24
    )

    cases = engine.correlate([
        user_creation,
        privileged_group_change,
    ])

    assert cases == []


def test_linux_correlated_case_contains_chronological_timeline():
    user_creation = Finding(
        title="Linux User Account Created",
        description="A new Linux user account was created.",
        severity="MEDIUM",
        mitre_id="T1136",
        recommendation="Verify whether the account creation was authorized.",
        evidence={"username": "soc-linux-test"},
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    privileged_group_change = Finding(
        title="Linux Privileged Group Membership Changed",
        description="A Linux user was added to the sudo group.",
        severity="HIGH",
        mitre_id="T1098.007",
        recommendation="Verify whether the privilege assignment was authorized.",
        evidence={
            "target_user": "soc-linux-test",
            "privileged_group": "sudo",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:05:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        privileged_group_change,
        user_creation,
    ])

    assert len(cases) == 1
    assert cases[0].timeline == [
        {
            "timestamp": "2026-07-15T10:00:00+00:00",
            "event": "Linux User Account Created",
        },
        {
            "timestamp": "2026-07-15T10:05:00+00:00",
            "event": (
                "Linux Privileged Group Membership Changed"
            ),
        },
    ]


def test_correlates_brute_force_followed_by_suspicious_powershell():
    brute_force = Finding(
        title="Possible Brute Force",
        description="Repeated failed logon attempts were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate the source IP and target account.",
        evidence={
            "source_ip": "192.168.1.50",
            "username": "Administrator",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    suspicious_powershell = Finding(
        title="Suspicious PowerShell",
        description="Suspicious PowerShell activity was detected.",
        severity="HIGH",
        mitre_id="T1059.001",
        recommendation="Investigate the PowerShell activity.",
        evidence={
            "matched_patterns": [
                "downloadstring",
            ],
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        brute_force,
        suspicious_powershell,
    ])

    assert len(cases) == 1
    assert cases[0].case_id == "CASE-001"
    assert cases[0].title == (
        "Potential Post-Compromise PowerShell Activity"
    )
    assert cases[0].severity == "Critical"
    assert cases[0].findings == [
        brute_force,
        suspicious_powershell,
    ]


def test_does_not_correlate_brute_force_and_powershell_on_different_hosts():
    brute_force = Finding(
        title="Possible Brute Force",
        description="Repeated failed logon attempts were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate the source IP and target account.",
        evidence={
            "source_ip": "192.168.1.50",
            "username": "Administrator",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="DC01",
            )
        ],
    )

    suspicious_powershell = Finding(
        title="Suspicious PowerShell",
        description="Suspicious PowerShell activity was detected.",
        severity="HIGH",
        mitre_id="T1059.001",
        recommendation="Investigate the PowerShell activity.",
        evidence={},
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        brute_force,
        suspicious_powershell,
    ])

    assert cases == []


def test_does_not_correlate_powershell_before_brute_force():
    brute_force = Finding(
        title="Possible Brute Force",
        description="Repeated failed logon attempts were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate the source IP and target account.",
        evidence={
            "source_ip": "192.168.1.50",
            "username": "Administrator",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    suspicious_powershell = Finding(
        title="Suspicious PowerShell",
        description="Suspicious PowerShell activity was detected.",
        severity="HIGH",
        mitre_id="T1059.001",
        recommendation="Investigate the PowerShell activity.",
        evidence={},
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        brute_force,
        suspicious_powershell,
    ])

    assert cases == []


def test_does_not_correlate_brute_force_and_powershell_outside_time_window():
    brute_force = Finding(
        title="Possible Brute Force",
        description="Repeated failed logon attempts were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate the source IP and target account.",
        evidence={
            "source_ip": "192.168.1.50",
            "username": "Administrator",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    suspicious_powershell = Finding(
        title="Suspicious PowerShell",
        description="Suspicious PowerShell activity was detected.",
        severity="HIGH",
        mitre_id="T1059.001",
        recommendation="Investigate the PowerShell activity.",
        evidence={},
        related_alerts=[
            make_alert(
                "2026-07-17T10:00:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    engine = CorrelationEngine(
        correlation_window_hours=24
    )

    cases = engine.correlate([
        brute_force,
        suspicious_powershell,
    ])

    assert cases == []


def test_post_compromise_powershell_case_contains_entities_and_timeline():
    brute_force = Finding(
        title="Possible Brute Force",
        description="Repeated failed logon attempts were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate the source IP and target account.",
        evidence={
            "source_ip": "192.168.1.50",
            "username": "Administrator",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    suspicious_powershell = Finding(
        title="Suspicious PowerShell",
        description="Suspicious PowerShell activity was detected.",
        severity="HIGH",
        mitre_id="T1059.001",
        recommendation="Investigate the PowerShell activity.",
        evidence={
            "matched_patterns": [
                "downloadstring",
            ],
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="JeanPc",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        suspicious_powershell,
        brute_force,
    ])

    assert len(cases) == 1

    assert cases[0].entities == {
        "host": "JeanPc",
        "target_user": "Administrator",
        "source_ip": "192.168.1.50",
    }

    assert cases[0].timeline == [
        {
            "timestamp": "2026-07-15T10:00:00+00:00",
            "event": "Possible Brute Force",
        },
        {
            "timestamp": "2026-07-15T10:10:00+00:00",
            "event": "Suspicious PowerShell",
        },
    ]


def test_correlates_linux_ssh_brute_force_followed_by_failed_sudo():
    ssh_brute_force = Finding(
        title="Linux SSH Brute Force",
        description="Repeated SSH authentication failures were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate the SSH authentication activity.",
        evidence={
            "source_ip": "192.168.1.50",
            "service": "sshd",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    failed_sudo = Finding(
        title="Linux Failed Sudo Activity",
        description="Repeated failed sudo activity was detected.",
        severity="HIGH",
        mitre_id="T1548.003",
        recommendation="Investigate the sudo activity.",
        evidence={
            "source_user": "soc-user",
            "target_user": "root",
            "command": "/usr/bin/id",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        ssh_brute_force,
        failed_sudo,
    ])

    assert len(cases) == 1
    assert cases[0].case_id == "CASE-001"
    assert cases[0].title == (
        "Potential Linux Post-Compromise "
        "Privilege Escalation"
    )
    assert cases[0].severity == "Critical"
    assert cases[0].findings == [
        ssh_brute_force,
        failed_sudo,
    ]


def test_does_not_correlate_linux_ssh_and_sudo_on_different_hosts():
    ssh_brute_force = Finding(
        title="Linux SSH Brute Force",
        description="Repeated SSH authentication failures were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate SSH activity.",
        evidence={
            "source_ip": "192.168.1.50",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    failed_sudo = Finding(
        title="Linux Failed Sudo Activity",
        description="Repeated failed sudo activity was detected.",
        severity="HIGH",
        mitre_id="T1548.003",
        recommendation="Investigate sudo activity.",
        evidence={
            "source_user": "soc-user",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="linux-02",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        ssh_brute_force,
        failed_sudo,
    ])

    assert cases == []


def test_does_not_correlate_failed_sudo_before_linux_ssh_brute_force():
    ssh_brute_force = Finding(
        title="Linux SSH Brute Force",
        description="Repeated SSH authentication failures were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate SSH activity.",
        evidence={
            "source_ip": "192.168.1.50",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    failed_sudo = Finding(
        title="Linux Failed Sudo Activity",
        description="Repeated failed sudo activity was detected.",
        severity="HIGH",
        mitre_id="T1548.003",
        recommendation="Investigate sudo activity.",
        evidence={
            "source_user": "soc-user",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        ssh_brute_force,
        failed_sudo,
    ])

    assert cases == []


def test_linux_post_compromise_case_contains_entities_and_timeline():
    ssh_brute_force = Finding(
        title="Linux SSH Brute Force",
        description="Repeated SSH authentication failures were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate SSH activity.",
        evidence={
            "source_ip": "192.168.1.50",
            "service": "sshd",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    failed_sudo = Finding(
        title="Linux Failed Sudo Activity",
        description="Repeated failed sudo activity was detected.",
        severity="HIGH",
        mitre_id="T1548.003",
        recommendation="Investigate sudo activity.",
        evidence={
            "source_user": "soc-user",
            "target_user": "root",
            "command": "/usr/bin/id",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T10:10:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        failed_sudo,
        ssh_brute_force,
    ])

    assert len(cases) == 1

    assert cases[0].entities == {
        "host": "linux-01",
        "source_ip": "192.168.1.50",
        "source_user": "soc-user",
        "target_user": "root",
    }

    assert cases[0].timeline == [
        {
            "timestamp": "2026-07-15T10:00:00+00:00",
            "event": "Linux SSH Brute Force",
        },
        {
            "timestamp": "2026-07-15T10:10:00+00:00",
            "event": "Linux Failed Sudo Activity",
        },
    ]


def test_consolidates_multiple_linux_ssh_and_sudo_findings():
    ssh_brute_force_1 = Finding(
        title="Linux SSH Brute Force",
        description="Repeated SSH authentication failures were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate SSH activity.",
        evidence={
            "source_ip": "192.168.188.1",
            "service": "sshd",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T07:45:45+00:00",
                agent_name="linux-01",
            )
        ],
    )

    ssh_brute_force_2 = Finding(
        title="Linux SSH Brute Force",
        description="Repeated SSH authentication failures were detected.",
        severity="HIGH",
        mitre_id="T1110",
        recommendation="Investigate SSH activity.",
        evidence={
            "source_ip": "192.168.188.1",
            "service": "sshd",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T07:48:41+00:00",
                agent_name="linux-01",
            )
        ],
    )

    failed_sudo_1 = Finding(
        title="Linux Failed Sudo Activity",
        description="Repeated failed sudo activity was detected.",
        severity="HIGH",
        mitre_id="T1548.003",
        recommendation="Investigate sudo activity.",
        evidence={
            "source_user": "yanots",
            "target_user": "root",
            "command": "/usr/bin/id",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T07:53:25+00:00",
                agent_name="linux-01",
            )
        ],
    )

    failed_sudo_2 = Finding(
        title="Linux Failed Sudo Activity",
        description="Repeated failed sudo activity was detected.",
        severity="HIGH",
        mitre_id="T1548.003",
        recommendation="Investigate sudo activity.",
        evidence={
            "source_user": "yanots",
            "target_user": "root",
            "command": "/usr/bin/id",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T07:53:37+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate([
        ssh_brute_force_1,
        ssh_brute_force_2,
        failed_sudo_1,
        failed_sudo_2,
    ])

    assert len(cases) == 1

    assert cases[0].findings == [
        ssh_brute_force_1,
        ssh_brute_force_2,
        failed_sudo_1,
        failed_sudo_2,
    ]

    assert cases[0].entities == {
        "host": "linux-01",
        "source_ip": "192.168.188.1",
        "source_user": "yanots",
        "target_user": "root",
    }

    assert cases[0].timeline == [
        {
            "timestamp": "2026-07-15T07:45:45+00:00",
            "event": "Linux SSH Brute Force",
        },
        {
            "timestamp": "2026-07-15T07:48:41+00:00",
            "event": "Linux SSH Brute Force",
        },
        {
            "timestamp": "2026-07-15T07:53:25+00:00",
            "event": "Linux Failed Sudo Activity",
        },
        {
            "timestamp": "2026-07-15T07:53:37+00:00",
            "event": "Linux Failed Sudo Activity",
        },
    ]


def test_enriches_windows_case_with_suspicious_powershell():
    account_created = Finding(
        title="User Account Created",
        description="New account created.",
        severity="MEDIUM",
        mitre_id="T1136",
        recommendation="Investigate account creation.",
        evidence={
            "created_user": "SOC-Test-User",
            "target_domain": "SOCLAB",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T08:00:00+00:00",
                agent_name="DC01",
            )
        ],
    )

    group_change = Finding(
        title="Privileged Group Membership Changed",
        description="Privilege change.",
        severity="HIGH",
        mitre_id="T1098.007",
        recommendation="Investigate.",
        evidence={
            "member_name":
                "CN=SOC-Test-User,CN=Users,DC=soclab,DC=local",
            "group_name": "Domain Admins",
            "target_domain": "SOCLAB",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T08:05:00+00:00",
                agent_name="DC01",
            )
        ],
    )

    powershell = Finding(
        title="Suspicious PowerShell",
        description="Suspicious PowerShell.",
        severity="HIGH",
        mitre_id="T1059.001",
        recommendation="Investigate.",
        evidence={},
        related_alerts=[
            make_alert(
                "2026-07-15T08:10:00+00:00",
                agent_name="DC01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate(
        [
            account_created,
            group_change,
            powershell,
        ]
    )

    assert len(cases) == 1
    assert len(cases[0].findings) == 3


def test_enriches_linux_case_with_failed_sudo():
    user = Finding(
        title="Linux User Account Created",
        description="User created.",
        severity="MEDIUM",
        mitre_id="T1136",
        recommendation="Investigate.",
        evidence={
            "username": "attacker-test",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T09:00:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    group = Finding(
        title="Linux Privileged Group Membership Changed",
        description="sudo added.",
        severity="HIGH",
        mitre_id="T1098.007",
        recommendation="Investigate.",
        evidence={
            "target_user": "attacker-test",
            "privileged_group": "sudo",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T09:05:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    sudo = Finding(
        title="Linux Failed Sudo Activity",
        description="Failed sudo.",
        severity="HIGH",
        mitre_id="T1548.003",
        recommendation="Investigate.",
        evidence={
            "source_user": "attacker-test",
            "target_user": "root",
        },
        related_alerts=[
            make_alert(
                "2026-07-15T09:10:00+00:00",
                agent_name="linux-01",
            )
        ],
    )

    engine = CorrelationEngine()

    cases = engine.correlate(
        [
            user,
            group,
            sudo,
        ]
    )

    assert len(cases) == 1
    assert len(cases[0].findings) == 3

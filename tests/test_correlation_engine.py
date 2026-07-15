from soc_tool.correlation.engine import CorrelationEngine
from soc_tool.models.finding import Finding
from soc_tool.models.alert import Alert

def make_alert(timestamp: str) -> Alert:
    return Alert(
        timestamp=timestamp,
        agent_name="DC01",
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
        evidence={
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

    """"""""""""

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

    engine = CorrelationEngine(correlation_window_hours=24)

    cases = engine.correlate([
        account_creation,
        group_membership,
    ])

    assert cases == []

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

    engine = CorrelationEngine(correlation_window_hours=24)

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
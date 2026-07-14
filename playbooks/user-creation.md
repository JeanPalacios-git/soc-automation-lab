# User Creation Investigation Playbook

## Purpose

Provide a repeatable SOC Level 1 triage workflow for new Windows and
Linux account creation events.

## Detection Context

The project identifies Windows account creation activity and Linux user
creation activity collected through Wazuh telemetry.

Relevant MITRE ATT&CK technique:

-   T1136 - Create Account

## Initial Triage

1.  Identify the affected host.
2.  Identify the newly created account.
3.  Identify the user or process responsible for the creation.
4.  Review the event timestamp.
5.  Determine whether the account is local or domain-based when the
    evidence allows.
6.  Review subsequent privileged group membership changes.
7.  Review related authentication and scripting findings.
8.  Validate the account against an approved request or administrative
    action.

## Investigation Questions

-   Is the new account expected?
-   Who created the account?
-   Is the creator authorized to provision users?
-   Was the account added to a privileged group?
-   Did the account authenticate shortly after creation?
-   Is the username unusual or designed to resemble an existing account?
-   Are there related suspicious findings on the same host?
-   Does the activity match an approved provisioning workflow?

## Escalation Criteria

Escalate when:

-   The account creation is unauthorized.
-   The creator is unexpected.
-   The new account receives privileged access.
-   The account is used immediately for suspicious authentication or
    scripting activity.
-   The account name appears deceptive or abnormal.
-   Authorization cannot be confirmed.

## Recommended Response

-   Preserve the account creation evidence.
-   Validate the account with the system owner or identity
    administrator.
-   Disable unauthorized accounts when approved.
-   Review group memberships and permissions.
-   Review authentication activity for the new account.
-   Search for related activity across other hosts.
-   Escalate when malicious account creation is suspected.

## False Positive Considerations

Possible benign causes include:

-   Employee onboarding.
-   Service account provisioning.
-   Approved local administrator activity.
-   Automated deployment workflows.
-   Application installation.
-   SOC lab testing.

## Analyst Closure Notes

Document:

-   Affected host
-   Created account
-   Creator
-   Event time
-   Account type when known
-   Group memberships
-   Related authentication activity
-   Authorization validation
-   Final disposition
-   Escalation or remediation actions

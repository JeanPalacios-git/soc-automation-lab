# Brute Force Investigation Playbook

## Purpose

Provide a repeatable SOC Level 1 triage workflow for repeated
authentication failures that may indicate password guessing or brute
force activity.

## Detection Context

This project generates a `Possible Brute Force` finding when multiple
failed Windows logon events are observed within a short time window.
Linux SSH authentication failures may also generate a
`Linux SSH Brute Force` finding.

Relevant MITRE ATT&CK technique:

-   T1110 - Brute Force

## Initial Triage

1.  Confirm the affected host and event time.
2.  Identify the source IP address.
3.  Identify the targeted username or account.
4.  Review the number of failed authentication attempts.
5.  Determine the first-seen and last-seen timestamps.
6.  Check whether a successful authentication occurred after the
    failures.
7.  Compare the activity with expected administrative or user behavior.

## Investigation Questions

-   Is the source IP internal, external, loopback, or otherwise
    expected?
-   Is the targeted account privileged?
-   Were multiple accounts targeted from the same source?
-   Did the failures occur in a short and repetitive pattern?
-   Was there a successful logon immediately after the failed attempts?
-   Is the activity associated with a known test, scanner, service, or
    administrator?
-   Are similar findings present on other agents?

## Escalation Criteria

Escalate when one or more of the following conditions are present:

-   A successful authentication follows repeated failures.
-   A privileged account is targeted.
-   The source is unknown or unexpected.
-   Multiple accounts or hosts are targeted.
-   The activity continues after the initial detection.
-   Additional suspicious activity is observed on the affected host.

## Recommended Response

-   Preserve relevant authentication evidence.
-   Validate the activity with the account owner or system
    administrator.
-   Review related logon events and source activity.
-   Reset or protect the account if compromise is suspected.
-   Block or contain the source when appropriate and authorized.
-   Escalate to the next investigation tier when compromise cannot be
    ruled out.

## False Positive Considerations

Possible benign causes include:

-   Forgotten passwords.
-   Stale service credentials.
-   Scheduled tasks using an old password.
-   Authorized security testing.
-   Misconfigured applications.
-   Administrative lab activity.

## Analyst Closure Notes

Document:

-   Source IP
-   Target account
-   Affected host
-   Time window
-   Failed attempt count
-   Related successful logons
-   Validation performed
-   Final disposition
-   Escalation or containment actions

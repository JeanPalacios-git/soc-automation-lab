# Persistence Investigation Playbook

## Purpose

Provide a repeatable SOC Level 1 workflow for reviewing activity that
may establish or maintain access to a system.

## Detection Context

Persistence is investigated by correlating security findings with
account creation, privilege changes, suspicious PowerShell activity, and
other administrative events observed by the analysis workflow.

Relevant MITRE ATT&CK tactic:

-   TA0003 - Persistence

## Initial Triage

1.  Identify the affected host and user.
2.  Review the finding timestamp and surrounding activity.
3.  Determine what system change occurred.
4.  Identify the process, command, script, or account associated with
    the change.
5.  Review related account creation and privilege modification findings.
6.  Check for suspicious PowerShell execution.
7.  Validate whether the change was authorized.

## Investigation Questions

-   Was a new local or domain account created?
-   Was an account added to a privileged group?
-   Did PowerShell execute suspicious script content?
-   Is the initiating user expected to perform administrative changes?
-   Did the activity occur during an approved maintenance window?
-   Are there related findings on the same host?
-   Does the activity match known lab or automation behavior?

## Escalation Criteria

Escalate when:

-   An unauthorized account was created.
-   A new account received privileged access.
-   Suspicious scripting is associated with the system change.
-   The initiating user is unexpected.
-   Multiple persistence-related behaviors occur on the same host.
-   Authorization cannot be confirmed.

## Recommended Response

-   Preserve the relevant event and command evidence.
-   Validate the change with the system owner or administrator.
-   Disable unauthorized accounts when approved.
-   Remove unauthorized privileged memberships when approved.
-   Review the affected host for related suspicious activity.
-   Escalate for deeper investigation if malicious persistence is
    suspected.

## False Positive Considerations

Possible benign causes include:

-   Approved administrator activity.
-   Deployment automation.
-   Account provisioning workflows.
-   Configuration management tools.
-   Authorized security testing.
-   SOC lab simulations.

## Analyst Closure Notes

Document:

-   Affected host
-   User or account involved
-   Observed change
-   Related command or script
-   Privilege impact
-   Authorization validation
-   Related findings
-   Final disposition
-   Escalation or remediation actions

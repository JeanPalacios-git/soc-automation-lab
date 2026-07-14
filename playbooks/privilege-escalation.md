# Privilege Escalation Investigation Playbook

## Purpose

Provide a repeatable SOC Level 1 triage workflow for privileged group
membership changes and failed privileged command activity.

## Detection Context

The project detects Windows privileged group membership changes and
Linux privileged group modifications. It also identifies repeated failed
`sudo` activity on Linux systems.

Relevant MITRE ATT&CK techniques include:

-   T1098 - Account Manipulation
-   T1548.003 - Sudo and Sudo Caching

## Initial Triage

1.  Identify the affected agent.
2.  Identify the account receiving or attempting privileged access.
3.  Identify the user that initiated the change or command.
4.  Review the event time.
5.  Review the privileged group or attempted command.
6.  Check related account creation findings.
7.  Check for suspicious PowerShell or authentication findings.
8.  Validate whether the activity was authorized.

## Investigation Questions

-   Is the target account expected to have administrative privileges?
-   Who initiated the privilege change?
-   Was the account recently created?
-   Is the privileged group sensitive?
-   On Linux, what command was attempted with `sudo`?
-   Were there repeated authentication failures?
-   Did the privilege activity occur outside expected administrative
    work?
-   Are there related findings on the same host or account?

## Escalation Criteria

Escalate when:

-   Privileged access was granted without authorization.
-   A newly created account receives privileged membership.
-   The initiating user is unknown or unexpected.
-   Repeated failed `sudo` attempts are followed by successful
    privileged activity.
-   Suspicious scripting or authentication activity is correlated with
    the event.
-   The activity cannot be explained by approved administration.

## Recommended Response

-   Preserve group membership and command evidence.
-   Validate the change with the responsible administrator.
-   Remove unauthorized privileged membership when approved.
-   Review recent activity performed by the affected account.
-   Review authentication events for the initiating and target users.
-   Escalate if account compromise or unauthorized privilege escalation
    is suspected.

## False Positive Considerations

Possible benign causes include:

-   Approved administrator changes.
-   Help desk or identity management workflows.
-   Automated provisioning.
-   Authorized maintenance.
-   Mistyped `sudo` passwords.
-   SOC lab testing.

## Analyst Closure Notes

Document:

-   Host
-   Initiating user
-   Target account
-   Privileged group or command
-   Event time
-   Authorization result
-   Related findings
-   Final disposition
-   Escalation or remediation actions

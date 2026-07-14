# SOC Automation Lab

Python-based SOC analysis and detection workflow integrated with Wazuh
SIEM telemetry.

The project retrieves security alerts from a Wazuh Indexer, normalizes
Windows and Linux events, executes custom detection logic, persists
analyst findings, and generates an interactive HTML dashboard for
investigation and triage.

## Project Overview

This lab was built to simulate part of a Security Operations Center
Level 1 workflow.

Instead of reviewing isolated SIEM alerts manually, the application
retrieves telemetry from a live Wazuh environment and applies custom
Python detection logic to identify security activity across Windows and
Linux systems.

The analysis pipeline converts raw security events into structured
findings containing severity, MITRE ATT&CK mapping, evidence,
recommendations, and related alerts.

Analysts can then review findings through an interactive report and
manage investigation status using a persistent triage workflow.

## Architecture

``` text
Windows Server / Linux Hosts
            |
            v
       Wazuh Agents
            |
            v
       Wazuh Manager
            |
            v
       Wazuh Indexer
            |
            v
   Python Alert Ingestion
            |
            v
     Alert Normalization
            |
            v
      Detection Engine
            |
            v
     Security Findings
            |
       +----+----+
       |         |
       v         v
 SQLite Store  HTML Dashboard
       |
       v
 Analyst Triage Workflow
```

## Detection Coverage

The analysis engine currently executes eight custom detections across
Windows and Linux telemetry.

### Windows Detections

  -----------------------------------------------------------------------
  Detection               Event Source            MITRE ATT&CK
  ----------------------- ----------------------- -----------------------
  Possible Brute Force    Windows Event ID 4625   T1110 - Brute Force

  Suspicious PowerShell   PowerShell Event ID     T1059.001 - PowerShell
                          4104                    

  Account Creation        Windows Event ID 4720   T1136.001 - Local
                                                  Account

  Group Membership Change Windows Event ID 4728   T1098 - Account
                                                  Manipulation
  -----------------------------------------------------------------------

### Linux Detections

  -----------------------------------------------------------------------
  Detection               Telemetry               MITRE ATT&CK
  ----------------------- ----------------------- -----------------------
  SSH Brute Force         Wazuh SSH               T1110 - Brute Force
                          authentication alerts   

  Linux User Creation     Linux account activity  T1136.001 - Local
                                                  Account

  Privileged Group        Linux group             T1098 - Account
  Membership              modification activity   Manipulation

  Failed Sudo Attempts    Wazuh sudo alerts       T1548.003 - Sudo and
                                                  Sudo Caching
  -----------------------------------------------------------------------

## Detection Pipeline

The application follows a structured detection workflow:

1.  Query security alerts from the Wazuh Indexer.
2.  Normalize Wazuh documents into Python `Alert` objects.
3.  Deduplicate Windows events using agent and event record identifiers.
4.  Execute independent detection modules through the analysis engine.
5.  Generate structured `Finding` objects.
6.  Assign deterministic finding fingerprints.
7.  Synchronize findings with a SQLite persistence layer.
8.  Retrieve open findings for analyst review.
9.  Generate an interactive SOC analysis dashboard.

Each finding contains:

-   Detection title
-   Severity
-   MITRE ATT&CK technique
-   Description
-   Investigation recommendation
-   Detection evidence
-   Related security alerts

## Time-Window Brute Force Detection

The Windows brute force detector groups failed authentication attempts
by source IP address and username.

Events are ordered chronologically and analyzed within a defined time
window.

Independent authentication campaigns are detected separately, preventing
unrelated failed logons from being merged into a single finding.

Example detection evidence:

``` text
Source IP: 127.0.0.1
Username: Administrator
Failed Attempts: 6
First Seen: 2026-07-13T09:22:42
Last Seen: 2026-07-13T09:22:46
```

## Suspicious PowerShell Detection

PowerShell Script Block Logging events are analyzed for suspicious
execution patterns.

The detector evaluates high-confidence indicators and combinations of
supporting patterns, including:

``` text
EncodedCommand
DownloadString
Invoke-WebRequest
Invoke-Expression
IEX
```

This approach avoids flagging every PowerShell execution and instead
focuses on script content associated with suspicious command execution
behavior.

## Analyst Dashboard

The generated HTML report provides an interactive interface for
reviewing security findings.

Dashboard capabilities include:

-   Executive security summary
-   Severity statistics
-   Operating system breakdown
-   Detection distribution
-   Finding navigation
-   Severity sorting
-   Operating system sorting
-   Collapsible evidence
-   MITRE ATT&CK references
-   Analyst recommendations
-   Finding status management

The interface is designed to make large sets of findings easier to
review without requiring analysts to scroll through a completely linear
report.

## Finding Persistence and Triage

Findings are assigned deterministic SHA-256 fingerprints based on
detection context, related alerts, and evidence.

A SQLite persistence layer stores analyst triage state.

This allows findings to retain investigation status between analysis
executions.

The workflow supports statuses such as:

``` text
OPEN
INVESTIGATING
RESOLVED
FALSE_POSITIVE
```

The goal is to simulate a basic SOC investigation lifecycle rather than
generating disposable one-time reports.

## Testing

The project includes unit tests for detection logic and separate
integration tests for live Wazuh connectivity.

Local tests can be executed without requiring the Wazuh environment:

``` powershell
pytest -m "not integration" -q
```

Integration tests validate communication with the live Wazuh lab:

``` powershell
pytest -m integration -q
```

Full test suite:

``` powershell
pytest -q
```

Current local and detection test coverage includes alert normalization,
API authentication, Wazuh clients, report generation components, and
Windows and Linux detection scenarios.

At the current project milestone:

``` text
35 passed
5 integration tests separated
```

## Project Structure

``` text
soc-automation-lab/
|
+-- examples/
|   +-- run_analysis.py
|
+-- src/
|   +-- soc_tool/
|       +-- api/
|       |   +-- alerts.py
|       |   +-- auth.py
|       |   +-- client.py
|       |   +-- indexer.py
|       |
|       +-- config/
|       |   +-- settings.py
|       |
|       +-- detections/
|       |   +-- account_creation.py
|       |   +-- brute_force.py
|       |   +-- engine.py
|       |   +-- group_membership.py
|       |   +-- linux_failed_sudo.py
|       |   +-- linux_privileged_group.py
|       |   +-- linux_ssh_brute_force.py
|       |   +-- linux_user_creation.py
|       |   +-- persistence.py
|       |   +-- suspicious_powershell.py
|       |
|       +-- models/
|       |   +-- alert.py
|       |   +-- finding.py
|       |   +-- report.py
|       |
|       +-- reports/
|           +-- generator.py
|           +-- templates/
|               +-- reports.html
|
+-- tests/
+-- launcher.py
+-- pyproject.toml
+-- requirements.txt
+-- .env.example
```

## Setup

### 1. Clone the repository

``` powershell
git clone https://github.com/JeanPalacios-git/soc-automation-lab.git
cd soc-automation-lab
```

### 2. Create a virtual environment

``` powershell
python -m venv .venv
```

### 3. Activate the environment

``` powershell
.venv\Scripts\Activate.ps1
```

### 4. Install the project

``` powershell
pip install -e .
```

### 5. Configure environment variables

Copy the example environment file:

``` powershell
Copy-Item .env.example .env
```

Configure the Wazuh API and Indexer connection values inside `.env`.

Do not commit the `.env` file.

## Usage

Run the SOC analysis workflow:

``` powershell
python examples/run_analysis.py
```

The application retrieves Wazuh alerts, executes the detection engine,
synchronizes findings, and generates:

``` text
soc_analysis_report.html
```

The project also includes a launcher that validates the local
environment and handles unavailable Wazuh Indexer connectivity
gracefully.

## Security Considerations

Sensitive Wazuh credentials are loaded through environment variables and
are not stored directly in source code.

The repository excludes:

``` text
.env
Python virtual environments
Python cache files
SQLite finding databases
Generated SOC reports
Build artifacts
Executables
Python package metadata
```

The `.env.example` file contains placeholder values only.

## Limitations

This project is a security lab and portfolio project, not a production
SIEM or SOAR platform.

Current limitations include:

-   Detection logic is intentionally focused on a defined set of Windows
    and Linux scenarios.
-   The application depends on telemetry generated by the connected
    Wazuh environment.
-   TLS certificate verification may be disabled in the isolated lab
    environment.
-   Detection thresholds are currently defined in detector logic.
-   The HTML dashboard is designed for local analyst workflows.
-   The persistence layer uses SQLite and is not intended for
    multi-analyst production deployments.

These limitations are intentionally documented to distinguish the lab
architecture from a production SOC platform.

## Skills Demonstrated

This project demonstrates practical experience with:

-   Security Operations workflows
-   SIEM alert analysis
-   Wazuh
-   Windows Security Events
-   Linux authentication telemetry
-   Detection engineering fundamentals
-   Python security automation
-   MITRE ATT&CK mapping
-   Alert normalization
-   Event deduplication
-   Time-window correlation
-   Finding persistence
-   Analyst triage workflows
-   SQLite
-   HTML report generation
-   Unit testing
-   Integration testing
-   Git version control

## Related Projects

This project is part of a larger SOC home lab portfolio:

-   Active Directory Enterprise Lab
-   Enterprise Wazuh SIEM Lab
-   SOC Automation Lab

The Active Directory and Linux systems generate security telemetry
collected by Wazuh and analyzed by this application.

## Author

**Jean Palacios**

Cybersecurity student focused on Blue Team operations, SOC analysis,
SIEM monitoring, and security automation.

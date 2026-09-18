# Detection 04 - Suspicious PowerShell Hidden Execution

## Overview

This detection identifies PowerShell processes launched with the `-WindowStyle Hidden` parameter. It was developed and tested in a controlled SOC laboratory environment using Windows process creation telemetry and Splunk.

## Detection Objective

Identify PowerShell execution using hidden-window behaviour that may warrant investigation in a real environment.

## Log Source

* **Log source:** Windows Security Event Log
* **Event ID:** 4688 — Process Creation
* **Splunk index:** `windows_security`
* **Telemetry:** Windows process creation events forwarded using Splunk Universal Forwarder
* **Detection window:** Previous 5 minutes

## SPL Detection Query

```spl
index=windows_security EventCode=4688 earliest=-5m
| search New_Process_Name="*\\WindowsPowerShell\\*\\powershell.exe"
| search Process_Command_Line="*-WindowStyle Hidden*"
| stats count as suspicious_powershell_events values(Process_Command_Line) as command_lines by Account_Name Creator_Process_Name
| where suspicious_powershell_events >= 1
| sort - suspicious_powershell_events
```

## Detection Logic

The query:

1. Searches Windows process creation events in the `windows_security` index.
2. Limits the search to the previous 5 minutes.
3. Identifies PowerShell processes.
4. Searches for the `-WindowStyle Hidden` parameter.
5. Groups matching events by account and parent process.
6. Returns events where at least one matching PowerShell execution is identified.

## Lab Result

The detection identified PowerShell execution using the hidden-window parameter on the Windows 11 test machine.

| Attribute            | Result                  |
| -------------------- | ----------------------- |
| Host                 | Windows 11 test machine |
| User                 | `nachi`                 |
| Event ID             | 4688                    |
| Process              | `powershell.exe`        |
| Parent Process       | `powershell.exe`        |
| Suspicious Parameter | `-WindowStyle Hidden`   |
| Detection Window     | 5 minutes               |
| Activity             | Controlled lab test     |
| Result               | Benign / No compromise  |

The triggering command was:

```text id="u9n0n7"
powershell.exe -WindowStyle Hidden -Command "Write-Output 'SOC Lab Test'"
```

## MITRE ATT&CK

**T1059.001 - PowerShell**

The activity was mapped to T1059.001 because PowerShell was used during the observed process execution.

The mapping identifies the use of PowerShell and does not, by itself, establish that the activity was malicious.

## Investigation Outcome

The detection was classified as a **True Positive - Benign Activity** because the configured detection condition was satisfied.

The command was intentionally generated as part of the controlled laboratory test and produced harmless output.

No evidence of malicious execution, persistence, exfiltration or confirmed compromise was identified.

**Severity:** Medium

**Status:** Closed / Benign Activity

## Recommended Response

In a real production environment, recommended response actions would include:

* Review the PowerShell command line and execution context.
* Identify the user and parent process responsible for the execution.
* Determine whether the PowerShell activity was authorised.
* Correlate the event with endpoint, authentication and network telemetry.
* Investigate additional PowerShell activity from the same host or user.
* Consider endpoint containment if malicious execution is confirmed.
* Tune the detection to reduce benign PowerShell alerts while retaining suspicious activity.

## Key Takeaway

PowerShell using hidden-window parameters can warrant investigation, but the parameter alone does not establish malicious behaviour. Command-line content, user context, parent process and surrounding telemetry should be assessed before classifying the activity as malicious.

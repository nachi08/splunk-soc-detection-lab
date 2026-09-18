# Incident Report 004 - Suspicious PowerShell Hidden Execution

## 1. Incident Overview

Splunk detected PowerShell execution using the `-WindowStyle Hidden` parameter on a Windows 11 test machine in the controlled SOC laboratory environment.

The event was recorded as Windows Security Event ID `4688` (Process Creation) and forwarded to Splunk using the Universal Forwarder.

The triggering command was:

`powershell.exe -WindowStyle Hidden -Command "Write-Output 'SOC Lab Test'"`

The command was intentionally generated as part of the controlled laboratory test and was confirmed to be benign.

---

## 2. Incident Details

| Attribute            | Details                                |
| -------------------- | -------------------------------------- |
| Incident             | Suspicious PowerShell Hidden Execution |
| Severity             | Medium                                 |
| Classification       | True Positive - Benign Activity        |
| Status               | Closed                                 |
| Host                 | Windows 11 test machine                |
| User                 | `nachi`                                |
| Event ID             | 4688                                   |
| Process              | `powershell.exe`                       |
| Parent Process       | `powershell.exe`                       |
| Suspicious Parameter | `-WindowStyle Hidden`                  |
| Detection Window     | Previous 5 minutes                     |
| Splunk Index         | `windows_security`                     |
| Telemetry            | Windows Process Creation               |
| MITRE ATT&CK         | T1059.001 — PowerShell                 |

---

## 3. Detection Logic

The detection identifies PowerShell process creation events containing the `-WindowStyle Hidden` parameter.

```spl
index=windows_security EventCode=4688 earliest=-5m
| search New_Process_Name="*\\WindowsPowerShell\\*\\powershell.exe"
| search Process_Command_Line="*-WindowStyle Hidden*"
| stats count as suspicious_powershell_events values(Process_Command_Line) as command_lines by Account_Name Creator_Process_Name
| where suspicious_powershell_events >= 1
| sort - suspicious_powershell_events
```

### Detection Condition

The detection triggers when at least one PowerShell process creation event containing `-WindowStyle Hidden` is identified within the previous 5 minutes.

---

## 4. Investigation

The investigation began by reviewing the Splunk alert and the underlying Windows process creation event.

The event was:

* **Event ID:** 4688
* **User:** `nachi`
* **Process:** `powershell.exe`
* **Parent Process:** `powershell.exe`

The command line contained:

`-WindowStyle Hidden`

The complete command was:

`powershell.exe -WindowStyle Hidden -Command "Write-Output 'SOC Lab Test'"`

The command was intentionally executed as part of the laboratory simulation.

Further investigation found no evidence of:

* Malicious execution
* Persistence
* Data exfiltration
* Confirmed compromise

---

## 5. MITRE ATT&CK Mapping

### T1059.001 - PowerShell

The activity was mapped to **T1059.001 - PowerShell** because PowerShell was used during the observed process execution.

The mapping identifies the use of PowerShell and does not, by itself, establish malicious activity.

---

## 6. Incident Classification

**Classification:** True Positive — Benign Activity

The configured detection condition was satisfied because a PowerShell process containing the `-WindowStyle Hidden` parameter was identified.

**Severity:** Medium

**Outcome:** Closed / Benign Activity

No malicious execution or confirmed compromise was identified.

---

## 7. Recommended Response Actions

The activity was generated in a controlled laboratory environment, so no production containment or remediation was performed.

In a real-world environment, recommended response actions would include:

* Review the PowerShell command line and execution context.
* Identify the user and parent process responsible for the execution.
* Determine whether the PowerShell activity was authorised.
* Correlate the event with endpoint, authentication and network telemetry.
* Investigate additional PowerShell activity from the same host or user.
* Consider endpoint containment if malicious execution is confirmed.
* Tune the detection to reduce benign PowerShell alerts while retaining suspicious activity.

---

## 8. Investigation Methodology

The investigation followed these steps:

1. Review the Splunk alert.
2. Identify the Windows host and user.
3. Review the process creation event.
4. Examine the PowerShell command line.
5. Review the parent process.
6. Determine whether the PowerShell activity was authorised.
7. Assess surrounding telemetry for evidence of malicious behaviour.
8. Classify the incident.
9. Map the activity to MITRE ATT&CK.
10. Document recommended response actions.

---

## 9. Lessons Learned

* PowerShell command-line visibility is valuable for endpoint threat detection.
* Hidden-window execution can warrant investigation but does not automatically indicate malicious activity.
* Command-line content should be reviewed alongside user and parent-process context.
* Process creation events can provide useful evidence for endpoint investigations.
* Detection rules should account for legitimate PowerShell activity to reduce unnecessary alerts.
* MITRE ATT&CK mappings should describe observed behaviour without automatically implying malicious intent.

---

## 10. Conclusion

The investigation confirmed that the Splunk detection successfully identified PowerShell execution using the `-WindowStyle Hidden` parameter.

The activity was intentionally generated in the controlled laboratory environment and executed a harmless command.

The event was therefore classified as **True Positive - Benign Activity**, with no evidence of malicious execution or confirmed compromise.

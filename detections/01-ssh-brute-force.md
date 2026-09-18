# Detection 01 - SSH Brute Force

## Overview

This detection identifies repeated failed SSH authentication attempts against a Linux host. It was developed and tested in a controlled SOC laboratory environment using Splunk and Linux authentication logs.

## Detection Objective

Identify potential SSH password-guessing activity by detecting multiple failed authentication attempts originating from the same source IP within a defined time period.

## Log Source

* **Log file:** `/var/log/auth.log`
* **Splunk index:** `linux_security`
* **Activity:** Failed SSH authentication attempts
* **Detection threshold:** 5 or more failed attempts within 5 minutes

## SPL Detection Query

```spl
index=linux_security "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts by src_ip
| search failed_attempts>=5
```

## Detection Logic

The query:

1. Searches the `linux_security` index for failed authentication events.
2. Extracts the source IP address from the log event.
3. Counts failed authentication attempts for each source IP.
4. Returns source IPs with 5 or more failed attempts.

## Lab Result

The detection identified repeated failed SSH authentication attempts originating from the Kali Linux VM.

| Attribute        | Result              |
| ---------------- | ------------------- |
| Source IP        | `192.168.110.128`   |
| Source           | Kali Linux VM       |
| Target           | Ubuntu host         |
| Target User      | `nachiket`          |
| Protocol         | SSH                 |
| Failed Attempts  | 10                  |
| Threshold        | 5+ within 5 minutes |
| Successful Login | None observed       |

## MITRE ATT&CK

**T1110.001 - Password Guessing**

The observed activity involved repeated failed authentication attempts against an SSH account, consistent with password-guessing behaviour.

## Investigation Outcome

The detection was classified as a **True Positive** for the configured detection condition.

The activity was generated as part of a controlled laboratory simulation. No successful SSH authentication or confirmed compromise was identified.

**Severity:** Medium

**Status:** Unsuccessful / No confirmed compromise

## Recommended Response

In a real production environment, recommended response actions would include:

* Validate the source IP and determine whether the activity is authorised.
* Review authentication logs for successful logins following the failed attempts.
* Investigate the targeted account for suspicious activity.
* Consider blocking or restricting the source if malicious activity is confirmed.
* Review SSH authentication controls and password policies.
* Tune detection thresholds based on normal authentication behaviour.

## Key Takeaway

Repeated failed SSH authentication attempts from a single source can indicate password-guessing activity. Detection thresholds should be investigated alongside authentication outcomes and surrounding context before determining whether an actual compromise occurred.

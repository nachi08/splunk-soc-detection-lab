# Incident Report 001 - SSH Brute Force

## 1. Incident Overview

Splunk detected repeated failed SSH authentication attempts against an Ubuntu host in the controlled SOC laboratory environment.

The activity originated from the Kali Linux VM and targeted the `nachiket` user account. The detection triggered after the configured threshold of 5 or more failed authentication attempts within 5 minutes.

A total of 10 failed SSH authentication attempts were observed from source IP `192.168.110.128`.

No successful SSH login was identified during the investigation.

---

## 2. Incident Details

| Attribute           | Details                       |
| ------------------- | ----------------------------- |
| Incident            | SSH Brute Force               |
| Severity            | Medium                        |
| Classification      | True Positive                 |
| Status              | Unsuccessful                  |
| Source IP           | `192.168.110.128`             |
| Source              | Kali Linux VM                 |
| Destination         | Ubuntu host                   |
| Target User         | `nachiket`                    |
| Protocol            | SSH                           |
| Failed Attempts     | 10                            |
| Detection Threshold | 5+ attempts within 5 minutes  |
| Log Source          | `/var/log/auth.log`           |
| Splunk Index        | `linux_security`              |
| MITRE ATT&CK        | T1110.001 — Password Guessing |

---

## 3. Detection Logic

The detection identifies repeated failed SSH authentication attempts originating from the same source IP.

```spl
index=linux_security "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts by src_ip
| search failed_attempts>=5
```

### Detection Condition

The alert triggers when a source IP generates **5 or more failed SSH authentication attempts** within the configured 5-minute evaluation period.

---

## 4. Investigation

The investigation began by reviewing the Splunk alert and the underlying Linux authentication events.

The source IP was identified as:

`192.168.110.128`

The IP originated from the Kali Linux VM used for attack simulation.

The authentication events showed repeated failed SSH password attempts against the `nachiket` account.

A total of **10 failed attempts** were observed.

The authentication logs were then reviewed for evidence of a successful login. No successful SSH authentication was identified.

---

## 5. MITRE ATT&CK Mapping

### T1110.001 - Password Guessing

The activity was mapped to **T1110.001 - Password Guessing** because repeated failed authentication attempts were observed against the SSH account.

**Tactic:** Credential Access

**Technique:** T1110 - Brute Force

**Sub-technique:** T1110.001 - Password Guessing

---

## 6. Incident Classification

**Classification:** True Positive

The configured detection condition was satisfied by the observed failed authentication attempts.

**Severity:** Medium

**Outcome:** Unsuccessful

No successful authentication or confirmed compromise was identified.

---

## 7. Recommended Response Actions

The activity was generated in a controlled laboratory environment, so no production containment or remediation was performed.

In a real-world environment, recommended response actions would include:

* Validate the source IP and determine whether the activity is authorised.
* Review authentication logs for successful logins following the failed attempts.
* Investigate the targeted account for suspicious activity.
* Consider blocking or restricting the source if malicious activity is confirmed.
* Review SSH authentication controls and password policies.
* Tune detection thresholds based on normal authentication behaviour.

---

## 8. Investigation Methodology

The investigation followed these steps:

1. Review the Splunk alert.
2. Identify the source IP and targeted account.
3. Review the underlying authentication events.
4. Count failed authentication attempts.
5. Check for successful authentication.
6. Determine whether the detection condition was satisfied.
7. Classify the incident.
8. Map the activity to MITRE ATT&CK.
9. Document recommended response actions.

---

## 9. Lessons Learned

* Security alerts require investigation rather than automatic assumption of compromise.
* Source IP extraction helps identify the origin of authentication activity.
* Detection thresholds can help identify abnormal authentication behaviour.
* Successful authentication events should be reviewed alongside failed attempts.
* MITRE ATT&CK mapping helps provide a consistent description of observed adversary behaviour.
* Detection thresholds should be reviewed and tuned according to normal authentication patterns.

---

## 10. Conclusion

The investigation confirmed repeated failed SSH authentication attempts from the Kali Linux VM against the Ubuntu host.

The configured Splunk detection successfully identified the simulated password-guessing activity after the threshold was exceeded.

Although the detection was a true positive, no successful SSH authentication or confirmed compromise was identified.

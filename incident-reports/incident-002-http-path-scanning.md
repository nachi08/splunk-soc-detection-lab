# Incident Report 002 - HTTP Path Scanning

## 1. Incident Overview

Splunk detected suspicious HTTP requests against an Apache web server in the controlled SOC laboratory environment.

The activity originated from the Kali Linux VM and targeted commonly accessed administrative and authentication paths:

* `/login`
* `/admin`
* `/wp-admin`

The detection triggered after 3 suspicious requests were observed within 15 minutes.

All three requests returned HTTP `404` responses, and no successful access was identified.

---

## 2. Incident Details

| Attribute           | Details                         |
| ------------------- | ------------------------------- |
| Incident            | HTTP Path Scanning              |
| Severity            | Medium                          |
| Classification      | True Positive                   |
| Status              | Unsuccessful                    |
| Source IP           | `192.168.110.128`               |
| Source              | Kali Linux VM                   |
| Destination         | Ubuntu Apache server            |
| HTTP Method         | GET                             |
| Target Paths        | `/login`, `/admin`, `/wp-admin` |
| Suspicious Requests | 3                               |
| Unique Paths        | 3                               |
| Response Status     | 404                             |
| Detection Threshold | 3+ requests within 15 minutes   |
| Log Source          | `/var/log/apache2/access.log`   |
| Splunk Index        | `web_security`                  |
| Sourcetype          | `apache:access`                 |
| MITRE ATT&CK        | T1595.003 — Wordlist Scanning   |

---

## 3. Detection Logic

The detection identifies repeated requests to commonly targeted web paths from the same source IP.

```spl
index=web_security
| rex "^(?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) .* \"(?<method>\w+) (?<uri>\S+) HTTP"
| search uri="/admin" OR uri="/login" OR uri="/wp-admin"
| stats count as suspicious_requests dc(uri) as unique_paths values(uri) as requested_paths by src_ip
| where suspicious_requests >= 3
| sort - suspicious_requests
```

### Detection Condition

The alert triggers when a source IP generates **3 or more requests** to the configured suspicious paths within the 15-minute evaluation period.

---

## 4. Investigation

The investigation began by reviewing the Splunk alert and the underlying Apache access logs.

The source IP was identified as:

`192.168.110.128`

The activity originated from the Kali Linux VM used for attack simulation.

Three suspicious HTTP GET requests were identified:

```text
/login
/admin
/wp-admin
```

Each path was requested once, resulting in:

* 3 suspicious requests
* 3 unique paths
* HTTP `404` responses

The HTTP responses indicated that the requested resources were not found.

No successful access to the targeted paths was identified during the investigation.

---

## 5. MITRE ATT&CK Mapping

### T1595.003 — Wordlist Scanning

The activity was mapped to **T1595.003 - Wordlist Scanning** because the simulated activity involved requesting multiple commonly targeted web paths as part of reconnaissance.

**Tactic:** Reconnaissance

**Technique:** T1595 — Active Scanning

**Sub-technique:** T1595.003 — Wordlist Scanning

---

## 6. Incident Classification

**Classification:** True Positive

The configured detection condition was satisfied by the observed suspicious HTTP requests.

**Severity:** Medium

**Outcome:** Unsuccessful

All requests returned HTTP `404` responses, and no successful access or confirmed compromise was identified.

---

## 7. Recommended Response Actions

The activity was generated in a controlled laboratory environment, so no production containment or remediation was performed.

In a real-world environment, recommended response actions would include:

* Validate the source IP and determine whether the activity is authorised.
* Review additional HTTP requests from the same source.
* Check whether any targeted paths returned successful responses.
* Correlate the activity with authentication, application and endpoint telemetry.
* Investigate the source if malicious scanning is confirmed.
* Review and tune detection thresholds based on normal web traffic.

---

## 8. Investigation Methodology

The investigation followed these steps:

1. Review the Splunk alert.
2. Identify the source IP and destination.
3. Review the underlying Apache access logs.
4. Identify the requested URIs.
5. Review HTTP response status codes.
6. Determine whether the detection condition was satisfied.
7. Check for evidence of successful access.
8. Classify the incident.
9. Map the activity to MITRE ATT&CK.
10. Document recommended response actions.

---

## 9. Lessons Learned

* Suspicious web requests should be investigated in the context of surrounding HTTP activity.
* Multiple targeted paths from the same source can indicate reconnaissance activity.
* HTTP response codes help determine whether a requested resource was successfully accessed.
* Unique-path counts can provide additional context when investigating scanning behaviour.
* Detection thresholds should be reviewed against normal application traffic.
* A scanning detection does not by itself indicate successful compromise.

---

## 10. Conclusion

The investigation confirmed suspicious HTTP path-scanning activity originating from the Kali Linux VM against the Ubuntu Apache server.

The Splunk detection successfully identified three requests to commonly targeted paths within the configured threshold.

All requests returned HTTP `404` responses, and no successful access or confirmed compromise was identified.

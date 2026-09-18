# Detection 02 - HTTP Path Scanning

## Overview

This detection identifies suspicious HTTP requests to commonly targeted administrative and authentication paths. It was developed and tested in a controlled SOC laboratory environment using Splunk and Apache web-server access logs.

## Detection Objective

Identify potential web reconnaissance or path-scanning activity by detecting repeated requests for known sensitive or commonly targeted paths from the same source IP.

## Log Source

* **Log file:** `/var/log/apache2/access.log`
* **Splunk index:** `web_security`
* **Sourcetype:** `apache:access`
* **Detection threshold:** 3 or more suspicious requests within 15 minutes

## SPL Detection Query

```
index=web_security
| rex "^(?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) .* \"(?<method>\w+) (?<uri>\S+) HTTP"
| search uri="/admin" OR uri="/login" OR uri="/wp-admin"
| stats count as suspicious_requests dc(uri) as unique_paths values(uri) as requested_paths by src_ip
| where suspicious_requests >= 3
| sort - suspicious_requests
```

## Detection Logic

The query:

1. Searches the `web_security` index for Apache web-server events.
2. Extracts the source IP, HTTP method and requested URI.
3. Filters requests targeting `/admin`, `/login` or `/wp-admin`.
4. Counts suspicious requests for each source IP.
5. Counts the number of unique paths requested.
6. Returns sources generating 3 or more suspicious requests.
7. Sorts results by the number of suspicious requests.

## Lab Result

The detection identified suspicious HTTP requests originating from the Kali Linux VM.

| Attribute           | Result                          |
| ------------------- | ------------------------------- |
| Source IP           | `192.168.110.128`               |
| Source              | Kali Linux VM                   |
| Destination         | Ubuntu Apache server            |
| Requests            | `/login`, `/admin`, `/wp-admin` |
| Suspicious Requests | 3                               |
| Unique Paths        | 3                               |
| HTTP Method         | GET                             |
| Response            | 404                             |
| Threshold           | 3+ requests within 15 minutes   |
| Successful Access   | None observed                   |

## MITRE ATT&CK

**T1595.003 - Wordlist Scanning**

The activity was mapped to T1595.003 because the simulated activity involved requests to multiple commonly targeted web paths as part of reconnaissance.

## Investigation Outcome

The detection was classified as a **True Positive** for the configured detection condition.

All three requests returned HTTP **404** responses, and no successful access or confirmed compromise was identified.

**Severity:** Medium

**Status:** Unsuccessful / No confirmed compromise

## Recommended Response

In a real production environment, recommended response actions would include:

* Validate the source IP and determine whether the activity is authorised.
* Review additional requests from the same source.
* Check whether any targeted paths returned successful responses.
* Correlate the activity with authentication, application and endpoint telemetry.
* Investigate the source if malicious scanning is confirmed.
* Review and tune the detection based on normal web traffic.

## Key Takeaway

Repeated requests to commonly targeted web paths can indicate reconnaissance or path-scanning activity. HTTP response codes and surrounding application activity should be reviewed to determine whether the scanning resulted in successful access or compromise.

# Detection 03 - High-Volume DNS Activity

## Overview

This detection identifies unusually high DNS query activity from a single source IP. It was developed and tested in a controlled SOC laboratory environment using Splunk and BIND9 DNS query logs.

## Detection Objective

Identify abnormal DNS query volume that may warrant further investigation for automated activity, reconnaissance or other suspicious DNS behaviour.

## Log Source

* **Log file:** `/var/log/named/query.log`
* **Splunk index:** `dns_security`
* **Sourcetype:** `bind9:query`
* **Detection threshold:** 20 or more DNS queries within 5 minutes

## SPL Detection Query

```spl
index=dns_security
| rex "client .* (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})#\d+ \((?<query_name>[^)]+)\): query: (?<query_domain>\S+) IN (?<query_type>\S+)"
| stats count as total_dns_queries dc(query_domain) as unique_domains values(query_domain) as queried_domains by src_ip
| where total_dns_queries >= 20
| sort - total_dns_queries
```

## Detection Logic

The query:

1. Searches the `dns_security` index for BIND9 DNS query events.
2. Extracts the source IP address.
3. Extracts the queried domain and DNS query type.
4. Counts DNS queries for each source IP.
5. Counts unique queried domains.
6. Returns sources generating 20 or more DNS queries.
7. Sorts results by total query volume.

## Lab Result

The detection identified high-volume DNS activity originating from the Kali Linux VM.

| Attribute              | Result                       |
| ---------------------- | ---------------------------- |
| Source IP              | `192.168.110.128`            |
| Destination DNS Server | `192.168.110.133`            |
| Source                 | Kali Linux VM                |
| DNS Server             | Ubuntu BIND9                 |
| Query Volume           | 20                           |
| Threshold              | 20+ queries within 5 minutes |
| Domain                 | `example.com`                |
| Query Types            | A / AAAA                     |
| Query Distribution     | 10 A + 10 AAAA               |
| Log Source             | `/var/log/named/query.log`   |

## MITRE ATT&CK

**No specific MITRE ATT&CK technique assigned.**

The observed activity demonstrated abnormal DNS query volume, but the investigation did not provide sufficient evidence of DNS tunnelling, malicious domains or confirmed reconnaissance/scanning behaviour.

## Investigation Outcome

The detection was classified as a **True Positive** for the configured detection condition.

The abnormal query volume was confirmed, but the activity used the benign domain `example.com` and did not provide evidence of malicious DNS behaviour or successful compromise.

**Severity:** Medium

**Status:** Unsuccessful / No confirmed compromise

## Recommended Response

In a real production environment, recommended response actions would include:

* Validate whether the DNS activity is expected or authorised.
* Review the queried domains and query types.
* Investigate patterns associated with potential DNS tunnelling.
* Correlate DNS activity with endpoint and network telemetry.
* Investigate or isolate the source if malicious behaviour is confirmed.
* Establish normal DNS query baselines and tune detection thresholds accordingly.

## Key Takeaway

High DNS query volume can be a useful anomaly indicator, but volume alone does not establish malicious activity. DNS detections should be investigated using query content, domain characteristics, timing, source context and correlated telemetry.

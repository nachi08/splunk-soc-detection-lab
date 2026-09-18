# Incident Report 003 - High-Volume DNS Activity

## 1. Incident Overview

Splunk detected unusually high DNS query activity originating from the Kali Linux VM and directed towards an Ubuntu BIND9 DNS server in the controlled SOC laboratory environment.

The detection triggered when 20 or more DNS query events were observed within 5 minutes.

A total of 20 queries were observed from source IP `192.168.110.128`, consisting of repeated A and AAAA queries for `example.com`.

No evidence of DNS tunnelling, malicious domains or successful compromise was identified.

---

## 2. Incident Details

| Attribute              | Details                      |
| ---------------------- | ---------------------------- |
| Incident               | High-Volume DNS Activity     |
| Severity               | Medium                       |
| Classification         | True Positive                |
| Status                 | Unsuccessful                 |
| Source IP              | `192.168.110.128`            |
| Source                 | Kali Linux VM                |
| Destination DNS Server | `192.168.110.133`            |
| DNS Server             | Ubuntu BIND9                 |
| Query Volume           | 20                           |
| Detection Threshold    | 20+ queries within 5 minutes |
| Queried Domain         | `example.com`                |
| Query Types            | A / AAAA                     |
| Query Distribution     | 10 A + 10 AAAA               |
| Log Source             | `/var/log/named/query.log`   |
| Splunk Index           | `dns_security`               |
| Sourcetype             | `bind9:query`                |
| MITRE ATT&CK           | No specific mapping assigned |

---

## 3. Detection Logic

The detection identifies unusually high DNS query volume originating from the same source IP.

```spl
index=dns_security
| rex "client .* (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})#\d+ \((?<query_name>[^)]+)\): query: (?<query_domain>\S+) IN (?<query_type>\S+)"
| stats count as total_dns_queries dc(query_domain) as unique_domains values(query_domain) as queried_domains by src_ip
| where total_dns_queries >= 20
| sort - total_dns_queries
```

### Detection Condition

The detection triggers when a source IP generates **20 or more DNS queries** within the configured 5-minute evaluation period.

---

## 4. Investigation

The investigation began by reviewing the Splunk alert and the underlying BIND9 DNS query logs.

The source IP was identified as:

`192.168.110.128`

The destination DNS server was:

`192.168.110.133`

The activity generated 20 DNS queries consisting of:

* 10 A queries
* 10 AAAA queries
* Repeated queries for `example.com`

The observed query volume satisfied the configured detection threshold.

Further investigation did not identify evidence of:

* DNS tunnelling
* Malicious domains
* Confirmed reconnaissance or scanning activity
* Successful compromise

The activity was therefore treated as abnormal DNS query volume rather than confirmed malicious DNS behaviour.

---

## 5. MITRE ATT&CK Assessment

**No specific MITRE ATT&CK technique was assigned.**

The available evidence was insufficient to confidently map the activity to a specific MITRE ATT&CK technique.

The detection identified abnormal query volume, but the observed queries involved the benign domain `example.com` and did not demonstrate DNS tunnelling or confirmed malicious reconnaissance/scanning behaviour.

---

## 6. Incident Classification

**Classification:** True Positive

The configured detection condition was satisfied because the observed DNS query volume reached the threshold.

**Severity:** Medium

**Outcome:** Unsuccessful / No confirmed compromise

The investigation identified abnormal DNS activity but did not establish malicious behaviour or compromise.

---

## 7. Recommended Response Actions

The activity was generated in a controlled laboratory environment, so no production containment or remediation was performed.

In a real-world environment, recommended response actions would include:

* Validate whether the DNS activity is expected or authorised.
* Review the queried domains and query types.
* Investigate patterns associated with potential DNS tunnelling.
* Correlate DNS activity with endpoint and network telemetry.
* Investigate or isolate the source if malicious behaviour is confirmed.
* Establish normal DNS query baselines and tune detection thresholds accordingly.

---

## 8. Investigation Methodology

The investigation followed these steps:

1. Review the Splunk alert.
2. Identify the source and destination IP addresses.
3. Review the underlying BIND9 query logs.
4. Analyse DNS query volume.
5. Review queried domains and query types.
6. Assess the activity for potential malicious DNS behaviour.
7. Determine whether the detection condition was satisfied.
8. Assess whether sufficient evidence existed for MITRE ATT&CK mapping.
9. Classify the incident.
10. Document recommended response actions.

---

## 9. Lessons Learned

* High DNS query volume can indicate activity that requires investigation.
* Query volume alone does not establish malicious behaviour.
* DNS queries should be assessed using domain characteristics, query types and surrounding context.
* Detection thresholds should be compared against normal DNS activity.
* Endpoint and network telemetry can provide additional context.
* MITRE ATT&CK mappings should only be assigned when the available evidence supports the technique.

---

## 10. Conclusion

The investigation confirmed that the configured Splunk detection successfully identified high-volume DNS activity from the Kali Linux VM.

Twenty DNS queries were observed within the configured threshold, consisting of repeated A and AAAA queries for `example.com`.

Although the detection condition was satisfied, the investigation did not identify sufficient evidence of DNS tunnelling, malicious domains or successful compromise.

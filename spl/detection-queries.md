# SPL Detection Queries

This file contains the Splunk SPL queries used for the four security detections developed and tested in the SOC laboratory environment.

---

## 01 - SSH Brute Force

**Objective:** Detect repeated failed SSH authentication attempts from the same source IP.

```spl
index=linux_security "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 5
```

**Detection threshold:** 5 or more failed attempts within 5 minutes.

**MITRE ATT&CK:** T1110.001 - Password Guessing

---

## 02 - HTTP Path Scanning

**Objective:** Detect repeated requests to commonly targeted web paths.

```spl
index=web_security
| rex "^(?<src_ip>\d{1,3}(?:\.\d{1,3}){3}) .* \"(?<method>\w+) (?<uri>\S+) HTTP"
| search uri="/admin" OR uri="/login" OR uri="/wp-admin"
| stats count as suspicious_requests dc(uri) as unique_paths values(uri) as requested_paths by src_ip
| where suspicious_requests >= 3
| sort - suspicious_requests
```

**Detection threshold:** 3 or more suspicious requests within 15 minutes.

**MITRE ATT&CK:** T1595.003 - Wordlist Scanning

---

## 03 - High-Volume DNS Activity

**Objective:** Detect unusually high DNS query activity from a single source IP.

```spl
index=dns_security
| rex "client .* (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})#\d+ \((?<query_name>[^)]+)\): query: (?<query_domain>\S+) IN (?<query_type>\S+)"
| stats count as total_dns_queries dc(query_domain) as unique_domains values(query_domain) as queried_domains by src_ip
| where total_dns_queries >= 20
| sort - total_dns_queries
```

**Detection threshold:** 20 or more DNS queries within 5 minutes.

**MITRE ATT&CK:** No specific technique assigned.

---

## 04 - Suspicious PowerShell Hidden Execution

**Objective:** Detect PowerShell process execution using the `-WindowStyle Hidden` parameter.

```spl
index=windows_security EventCode=4688 earliest=-5m
| search New_Process_Name="*\\WindowsPowerShell\\*\\powershell.exe"
| search Process_Command_Line="*-WindowStyle Hidden*"
| stats count as suspicious_powershell_events values(Process_Command_Line) as command_lines by Account_Name Creator_Process_Name
| where suspicious_powershell_events >= 1
| sort - suspicious_powershell_events
```

**Detection condition:** At least one matching PowerShell process creation event within the previous 5 minutes.

**MITRE ATT&CK:** T1059.001 - PowerShell

---

## Detection Summary

| Detection | Data Source | Threshold | MITRE ATT&CK |
|---|---|---|---|
| SSH Brute Force | Linux `auth.log` | 5+ failed attempts | T1110.001 |
| HTTP Path Scanning | Apache access logs | 3+ suspicious requests | T1595.003 |
| High-Volume DNS | BIND9 query logs | 20+ queries | No specific mapping |
| Suspicious PowerShell | Windows Event ID 4688 | 1+ matching event | T1059.001 |

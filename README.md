# Splunk SOC Detection & Incident Investigation Lab

A hands-on SOC laboratory project focused on **SIEM-based security monitoring, threat detection, alert investigation and incident reporting using Splunk**.

The lab was developed in a controlled environment to simulate common security events across Linux, web-server, DNS and Windows endpoint telemetry. Detection rules were created using **Splunk Search Processing Language (SPL)** and investigated through structured SOC-style workflows.

## Objectives

* Build practical experience with SIEM-based security monitoring
* Ingest and analyse security-relevant logs using Splunk
* Develop SPL-based detection rules
* Investigate simulated security alerts
* Extract and analyse indicators such as source IPs, requested paths, DNS queries and process command lines
* Classify security events based on available evidence
* Map observed behaviour to MITRE ATT&CK where sufficient evidence exists
* Document investigation findings and recommended response actions

## Lab Environment

The project uses a controlled virtualised security laboratory containing:

* **Splunk Enterprise** - SIEM and security log analysis
* **Kali Linux** - attack simulation and testing
* **Ubuntu** - Linux server environment
* **Apache** - web-server telemetry
* **BIND9** - DNS telemetry
* **Windows 11 test machine** - endpoint telemetry
* **Splunk Universal Forwarder** - Windows event forwarding

## Detection Scenarios

| #  | Detection                              | Log Source                     | Detection Threshold / Condition                          
| MITRE ATT&CK           
| -- | -------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------|
| 01 | SSH Brute Force                        | `/var/log/auth.log`            | 5+ failed SSH authentication attempts within 5 minutes                            | T1110.001 - Password Guessing |
| -- | -------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------|      
| 02 | HTTP Path Scanning                     | `/var/log/apache2/access.log`  | 3+ requests to suspicious paths within 15 minutes                                 | T1595.003 - Wordlist Scanning |
| -- | -------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------|        
| 03 | High-Volume DNS Activity               | `/var/log/named/query.log`     | 20+ DNS queries within 5 minutes                                                  
| No specific mapping assigned  |
| -- | -------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------|      
| 04 | Suspicious PowerShell Hidden Execution | Windows Security Event ID 4688 | PowerShell process containing `-WindowStyle Hidden` within the previous 5 minutes | T1059.001 - PowerShell        |
| -- | -------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------|


## 01 - SSH Brute Force Detection

Splunk was configured to identify repeated failed SSH authentication attempts against the Ubuntu host.

The simulated activity originated from the Kali Linux VM and targeted the `nachiket` account. The detection triggered after the configured threshold of five or more failed attempts within five minutes.

During the investigation, **10 failed attempts** were observed from source IP `192.168.110.128`, with no successful SSH authentication identified.

**MITRE ATT&CK:** T1110.001 - Password Guessing

**Key investigation points:**

* Source IP identification
* Failed authentication count
* Target username
* Authentication success/failure review
* Detection threshold validation

## 02 - HTTP Path Scanning Detection

The Apache web-server logs were analysed to identify requests for commonly targeted administrative or authentication paths.

The simulated activity generated requests for:

* `/login`
* `/admin`
* `/wp-admin`

The detection triggered when three or more suspicious requests were observed within 15 minutes.

All three requests returned HTTP **404** responses, and no successful access was identified.

**MITRE ATT&CK:** T1595.003 - Wordlist Scanning

**Key investigation points:**

* Source IP
* HTTP method
* Requested URI
* Number of suspicious requests
* Number of unique paths
* HTTP response status

## 03 - High-Volume DNS Activity Detection

Splunk was used to identify unusually high DNS query volume from a single source.

The detection triggered when 20 or more DNS query events were observed within five minutes. The simulated activity originated from `192.168.110.128` and generated repeated queries for `example.com`, including A and AAAA records.

The investigation identified abnormal query volume but **did not provide sufficient evidence of DNS tunnelling, malicious domains or successful compromise**.

For this reason, no specific MITRE ATT&CK technique was assigned to this detection.

**Key investigation points:**

* Source IP
* Destination DNS server
* Query volume
* Unique domains
* Query types
* Potential tunnelling indicators
* Baseline comparison

## 04 - Suspicious PowerShell Hidden Execution

Windows Security Event ID **4688** was analysed to detect PowerShell processes using the `-WindowStyle Hidden` parameter.

The event was generated on a Windows 11 test machine and forwarded to Splunk using the Universal Forwarder.

The triggering command was a controlled lab test:

`powershell.exe -WindowStyle Hidden -Command "Write-Output 'SOC Lab Test'"`

The detection was classified as a **true positive for the configured detection condition**, but the command itself was benign and no malicious execution, persistence, exfiltration or compromise was identified.

**MITRE ATT&CK:** T1059.001 - PowerShell

The MITRE mapping reflects the observed use of PowerShell and does not by itself indicate malicious activity.

## Investigation Methodology

The investigations followed a structured SOC-style workflow:

1. **Review the alert**
2. **Identify the triggering condition**
3. **Examine the underlying logs**
4. **Extract relevant indicators**
5. **Correlate related events**
6. **Determine whether the detection condition was satisfied**
7. **Assess whether malicious activity or compromise was supported by the evidence**
8. **Classify the incident**
9. **Map to MITRE ATT&CK where appropriate**
10. **Document recommended response actions**

## Incident Classification

The simulated incidents demonstrated that a detection being triggered does not automatically mean that a system has been compromised.

The investigations included:

* **True positive / unsuccessful** - SSH brute force
* **True positive / unsuccessful** - HTTP path scanning
* **True positive detection / abnormal activity without confirmed malicious behaviour** - High-volume DNS
* **True positive detection / benign activity** - Suspicious PowerShell hidden execution

All investigations were performed in a controlled laboratory environment.

## Key Learning Outcomes

This project provided practical experience with:

* Splunk SIEM operations
* SPL query development
* Security log analysis
* Alert triage
* Detection engineering
* IOC identification
* Authentication event analysis
* Web-server log investigation
* DNS telemetry analysis
* Windows process creation telemetry
* False-positive and benign-activity assessment
* MITRE ATT&CK mapping
* Incident documentation
* Detection threshold and baseline considerations

## Repository Structure

```
splunk-soc-detection-lab/
│
├── README.md
│
├── detections/
│   ├── 01-ssh-brute-force.md
│   ├── 02-http-path-scanning.md
│   ├── 03-high-volume-dns.md
│   └── 04-suspicious-powershell.md
│
├── incident-reports/
│   ├── incident-001-ssh-brute-force.md
│   ├── incident-002-http-path-scanning.md
│   ├── incident-003-high-volume-dns.md
│   └── incident-004-suspicious-powershell.md
│
├── spl/
│   └── detection-queries.md
│
└── screenshots/
```

## Disclaimer

This project was conducted in a controlled laboratory environment for cybersecurity learning and practical SOC development.

Attack simulations and security testing were performed against systems within the lab environment. Response actions described in the incident reports represent **recommended actions for a real-world environment** rather than containment or remediation performed against production systems.

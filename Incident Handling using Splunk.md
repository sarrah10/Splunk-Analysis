# Incident Handling Using Splunk  
## Website Defacement Investigation – Wayne Enterprises

---

## Introduction

This repository documents a **complete Incident Handling investigation** performed using **Splunk SIEM**.  
The scenario involves a **successful website defacement attack** against Wayne Enterprises’ public-facing web server:

http://www.imreallynotbatman.com

The objective of this investigation was to:
- Identify how the attacker gained access
- Trace attacker activity inside the network
- Map each action to the **7 phases of the Cyber Kill Chain**
- Use **Splunk SPL**, log correlation, and **OSINT** to uncover the full attack story

All logs analyzed during this investigation were available in:

```
index = botsv1
```


This investigation falls under the **Detection and Analysis** phase of the **Incident Handling Life Cycle**.

---

## Incident Handling Life Cycle

### 1. Preparation

The preparation phase focuses on organizational readiness against attacks.  
Wayne Enterprises had already implemented:

- Splunk SIEM
- Log ingestion from:
  - Web servers
  - Firewalls
  - IDS (Suricata)
  - Sysmon
  - Windows Event Logs
- Proper visibility into both **network-centric** and **host-centric** activities

This preparation enabled a successful post-incident investigation.

---

### 2. Detection and Analysis

This phase involves:
- Detecting suspicious activity
- Investigating alerts
- Root cause analysis
- Threat hunting

All investigation steps documented below were conducted in this phase.

---

### 3. Containment, Eradication, and Recovery

Although not performed directly in this lab, this phase would normally include:
- Isolating compromised hosts
- Removing malicious files
- Restoring services securely

---

### 4. Post-Incident Activity (Lessons Learned)

- Identify security gaps
- Improve detection rules
- Harden authentication mechanisms
- Train SOC and IT teams

---

## Log Sources Used

| Log Source | Description |
|----------|-------------|
| wineventlog | Windows Event Logs |
| winRegistry | Registry changes |
| XmlWinEventLog | Sysmon logs |
| fortigate_utm | Fortinet firewall logs |
| iis | IIS web server logs |
| Nessus:scan | Vulnerability scan results |
| Suricata | IDS alerts |
| stream:http | HTTP network traffic |
| stream:dns | DNS traffic |
| stream:icmp | ICMP traffic |

---

## Cyber Kill Chain Investigation

---

## Reconnaissance Phase

### Objective
Identify any scanning or probing attempts against the web server.

---

### Step 1: Identify logs referencing the target domain
```
index=botsv1 imreallynotbatman.com
```

This search revealed activity in multiple sourcetypes:
- stream:http
- suricata
- fortigate_utm
- iis

---

### Step 2: Analyze HTTP traffic
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http
```

The `src_ip` field revealed two source IPs:
- `40.80.148.42`
- `23.22.63.114`

The IP `40.80.148.42` generated a significantly higher volume of requests.

---

### Step 3: Validate reconnaissance using IDS logs
```
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
```

Suricata alerts confirmed scanning activity.

### Findings
- IP `40.80.148.42` was scanning the web server
- Scanner identified as **Acunetix**

---

## Exploitation Phase

### Objective
Determine how the attacker gained access to the server.

---

### Step 1: Identify request volume by source IP
```
index=botsv1 imreallynotbatman.com sourcetype=stream*
| stats count(src_ip) as Requests by src_ip
| sort - Requests
```

---

### Step 2: Focus on inbound traffic to the web server
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
```

Observed HTTP methods:
- High volume of `POST` requests

---

### Step 3: Identify CMS and admin panel

Fields such as `uri`, `uri_path`, and `http_referrer` revealed **Joomla CMS**.

Admin login path:
```
/joomla/administrator/index.php
```

---

### Step 4: Analyze POST requests to admin login
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
http_method=POST
uri="/joomla/administrator/index.php"
```

---

### Step 5: Identify brute-force activity
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
http_method=POST
uri="/joomla/administrator/index.php"
| table _time uri src_ip dest_ip form_data
```

Observations:
- Username always `admin`
- Multiple password attempts
- Rapid login attempts indicating automation

---

### Step 6: Extract passwords using Regex
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
http_method=POST form_data=usernamepasswd*
| rex field=form_data "passwd=(?<creds>\w+)"
| table src_ip creds
```
---

### Step 7: Analyze user-agent behavior
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
http_method=POST form_data=usernamepasswd*
| rex field=form_data "passwd=(?<creds>\w+)"
| table _time src_ip uri http_user_agent creds
```

### Findings
- IP `23.22.63.114` used Python script for brute force
- IP `40.80.148.42` logged in via browser
- One successful login identified

---

## Installation Phase

### Objective
Determine if malware or payloads were uploaded and executed.

---

### Step 1: Search for executable uploads
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
```

Discovered uploaded files:
- `3791.exe`
- `agent.php`

---

### Step 2: Confirm upload source
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
"part_filename{}"="3791.exe"
```

---

### Step 3: Check for execution on host
```
index=botsv1 "3791.exe"
```

---

### Step 4: Confirm execution using Sysmon
```
index=botsv1 sourcetype="XmlWinEventLog" EventCode=1 "3791.exe"
```

### Findings
- `3791.exe` was successfully executed on the server

---

## Command and Control Phase

### Objective
Identify outbound communication from the compromised server.

---

### Step 1: Analyze Suricata logs (outbound)
```
index=botsv1 src=192.168.250.70 sourcetype=suricata
```

Observed outbound traffic from the web server to external IPs.

---

### Step 2: Pivot into suspicious destination IP
```
index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
```

Observed downloads including:
- PHP files
- JPEG file

---

## Actions on Objectives

### Objective
Identify how the website was defaced.

---

### Step 1: Investigate suspicious file
```
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg"
dest_ip="192.168.250.70"
| table _time src dest_ip http.hostname url
```

### Findings
- File downloaded from attacker-controlled domain
- Used to deface the website

---

## Weaponization Phase

### Objective
Identify attacker infrastructure using OSINT.

---

### Domain Identified

prankglassinebracket.jumpingcrab.com


---

### OSINT Platforms Used
- Robtex
- VirusTotal
- DomainTools

---

### Findings
- Multiple masquerading domains
- IP `23.22.63.114` linked to attacker
- Email discovered:
Lillian.rose@po1s0n1vy.com

---

## Delivery Phase

### Objective
Identify secondary malware associated with the attacker.

---

### Threat Intelligence Platforms
- ThreatMiner
- VirusTotal
- Hybrid Analysis

---

### Malware Identified
- Name: `MirandaTateScreensaver.scr.exe`
- MD5:
```
c99131e0169171935c5ac32615ed6261
```

---

## Conclusion

This investigation successfully reconstructed a **complete cyber attack lifecycle** using Splunk SIEM.

### Key Outcomes
- Reconnaissance via Acunetix
- Successful brute-force attack on Joomla admin
- Malware upload and execution
- Command-and-Control communication established
- Website defaced
- Attacker infrastructure identified
- Secondary malware delivery discovered

---

## Skills Demonstrated

- Incident Handling
- Splunk SPL
- Regex extraction
- Log correlation
- Cyber Kill Chain mapping
- Threat Intelligence analysis
- SOC investigation workflow

---

# SIEM Log Analysis – Windows, Linux & Web Logs

## Overview

When analysing logs using a Security Information and Event Management (SIEM) platform, analysts rely on multiple log sources to gain visibility into system activity, detect threats, and investigate incidents.

This guide covers:
- Windows Logs
- Linux Logs
- Web Application Logs
- Practical Splunk Detection Queries

---

# Windows Logs

When analysing Windows environments in a SIEM, two primary log sources are used:

- WinEventLogs
- Sysmon

Sysmon must be installed and configured separately before logs can be collected.

Combining both log sources provides strong visibility into attacker behaviour.


## Sysmon vs WinEventLogs

### Sysmon

Sysmon (System Monitor) is an advanced Windows logging tool that records detailed system activity.

It provides visibility into:
- Process execution
- Network connections
- Process injection
- Registry changes
- File creation activity



## Malicious Process Execution

### Scenario

An alert indicates execution of a suspicious encoded PowerShell command.

### Splunk Query
```
index=winenv EventCode=1 powershell AND EncodedCommand
| table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine
```
### Investigation Findings

- Host: WINHOST05
- Malicious file executed from `C:\Users\Public`
- cmd.exe launched PowerShell using an encoded command

This indicates malicious execution activity.



## Suspicious Network Connection

A follow-up alert shows suspicious outbound communication.

### Splunk Query
```
index=winenv EventCode=3 ComputerName=WINHOST05
| table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol
```

### Findings

- Suspicious process: PPn423.exe
- Executed from Temp directory
- Destination IP: 83.222.191.2
- Destination Port: 9999

Recommendation: Validate IP using Threat Intelligence platforms.



## WinEventLogs

Windows contains over 200 log channels. The most commonly analysed are:

- Security Logs
- System Logs
- Application Logs



## Windows Security Logs

Security logs help analysts detect:

- Authentication attempts
- Account creation or modification
- File and registry access
- Process execution
- Policy changes
- Log clearing activity



### Detecting New User Creation

### Splunk Query
```
index=winenv EventCode=4720 OR EventCode=4722
| table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords
```
### Findings

- Backup user account created
- Created by ted-admin
- Indicates attacker persistence



## Windows System Logs

System logs capture OS and service-related activity.

Useful for detecting:
- Persistence
- Privilege escalation
- Malicious services



### Suspicious Service Creation
```
index=winenv EventCode=7045 OR EventCode=7036 ComputerName=WINHOST05
| table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message
```
### Findings

- Service Name: User Updates
- Executable: RNSfnsjdf.exe
- Running as SYSTEM account

Likely privilege escalation attempt.

---

# Linux Logs

Common Linux SIEM data sources:

- auth.log
- syslog



## Authentication Logs (auth.log)

Tracks:
- User login attempts
- SSH access
- sudo usage
- Privilege escalation



### Unusual SSH Login Activity

Alert: Suspicious SSH login to ubuntu user.
```
index=linux source="auth.log" ubuntu process=sshd
| search "Accepted password" OR "Failed password"
```
### Findings

- Multiple failed attempts followed by success
- Likely brute-force attack

Escalate to SOC L2.



## Privilege Escalation Behaviour
```
index=linux source="auth.log" su
| sort + _time
```

### Findings

- Attacker gained root access
- Additional logs required for full investigation



## System Logs (syslog)

System logs capture:
- Service activity
- Cron jobs
- Background processes



### Persistence via Cron Jobs

```
index=linux sourcetype=syslog ("CRON" OR "cron")
| search ("python" OR "perl" OR "ruby" OR ".sh" OR "bash" OR "nc")
```

### Findings

- Script `/tmp/pnr5433sw.sh` executed every 5 minutes
- Perl reverse shell connecting to 10.10.101.12:9999

Indicates persistence mechanism.



### Additional Linux Monitoring Tools

Common enterprise tools include:
- auditd
- osquery

---

# Web Application Logs

Web servers generate valuable security logs.

Common sources:
- Apache
- Nginx

Important log types:
- Access Logs
- Error Logs

These help detect:
- Scanning activity
- Web attacks
- Web shells
- Brute force attempts
- DDoS attacks



## Brute Force Activity (WordPress Login)

### Detection Strategy

- Monitor `/wp-login.php`
- Filter POST requests
- Detect repeated login attempts

```
index=* method=POST uri_path="/wp-login.php"
| bin _time span=5m
| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 25
| table referer_domain clientip UserAgent uri_path count status
```

### Findings

- IP: 167.172.41.141
- 160 login attempts
- User-Agent identified as Hydra brute-force tool



## Possible Web Shell Detection

```
index=*
| search status=200 AND uri_path IN(*.php, *.phtm, *.asp, *.aspx, *.jsp, *.exe) AND (method=POST AND method=GET)
| stats values(status) as status values(useragent) as UserAgent values(method) as method values(uri) as uri values(clientip) as clientip count by referer_domain
| where count > 2
| table referer_domain count method status clientip UserAgent uri
```

### Findings

- Suspicious file detected: 505.php
- Possible web shell activity

Further investigation required.



## DDoS Activity Detection

Indicators:
- Status code 503
- High request volume

```
index=* status=503
| bin _time span=10m
| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 100000
| table _time referer_domain clientip UserAgent uri_path count status
```

### Findings

- Over 1.5 million requests detected
- Service unavailable for 10 minutes

Confirmed possible DDoS attack.

---

# Key Takeaways

- Combine multiple log sources for complete visibility
- Sysmon provides deep Windows telemetry
- Security logs reveal attacker persistence
- Linux auth.log exposes login abuse
- syslog helps detect persistence mechanisms
- Web logs uncover external attacks

---

# Author

Sarrah Lokhandwala  
Cybersecurity | SOC Analysis | SIEM Investigation

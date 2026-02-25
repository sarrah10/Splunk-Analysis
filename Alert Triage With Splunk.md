# Alert Triage With Splunk

## Overview

This document covers real-world SOC analyst investigations using Splunk SIEM.  
Three alert scenarios are analysed:

1. Initial Access Alert (Linux)
2. Persistence Alert (Windows)
3. Web Shell Alert (Web Server)

Each scenario demonstrates the workflow followed by a SOC Level 1 Analyst during alert triage.

---

# Initial Access Alert (Linux)

## Alert Scenario

You have started your first shift as a SOC Analyst at an MSSP.  
A new alert appears indicating possible brute-force activity.

### Alert Details

- **Alert Name:** Brute Force Activity Detection  
- **Time:** 17/09/2025 09:00:21 AM  
- **Target Host:** tryhackme-2404  
- **Source IP:** 10.10.242.248  

Logs Location: It was practice log inside machine.

```
index=linux-alert
```

## Investigation Approach

Key observations:

- Source IP is **local** → attacker may already be inside the network.
- Host information unknown (likely organisational server).
- Activity occurs during working hours.


## Step 1 — Review Login Activity

Search successful, failed, and invalid login attempts.

```
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
| sort + _time
```

### Findings

- Large number of authentication attempts.
- Multiple invalid users detected.
- Possible account enumeration.


## Step 2 — Identify Targeted Users

```
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd \d+\d+:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:.\d{1,3}){3})"
| eval process="sshd"
| stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```

### Findings

- Four users targeted.
- `john.smith` received **503 login attempts**.

➡️ Clear brute-force indicator.


## Step 3 — Confirm Successful Access

```
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd \d+\d+:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:.\d{1,3}){3})"
| eval process="sshd"
| stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```

### Result

- Successful login detected for **john.smith**
- Attack classified as **True Positive**

✅ Escalate to SOC L2 & Incident Response.

---

## Investigation Answers

### 1. Failed login attempts

```
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
```

**Answer:** 500



### 2. Duration of attack

```
index="linux-alert" sourcetype="linux_secure" 10.10.242.248 "Failed password for" "john.smith"
| stats earliest(_time) as start latest(_time) as end
| eval duration_minutes=round((end-start)/60,0)
| table duration_minutes
```

**Answer:** 5 minutes



### 3. Privilege escalation account

```
index="linux-alert" sourcetype="linux_secure" john.smith (sudo OR su OR "Successful su" OR "session opened")
```

**Answer:** root



### 4. Persistence account created


index="linux-alert" "useradd"


**Answer:** system-utm

---

# Persistence Alert (Windows)

## Alert Scenario

A suspicious scheduled task creation alert is triggered.

### Alert Details

- **Alert Name:** Potential Task Scheduler Persistence Identified  
- **Time:** 30/08/2025 10:06:07 AM  
- **Host:** WIN-H015  
- **User:** oliver.thompson  
- **Task Name:** AssessmentTaskOne  

Logs Location:

```
index=win-alert
```


## Investigation Approach

### Host Analysis

- Host prefix `WIN` → Workstation

### User Analysis

- User role: **System Engineer**
- Verify whether activity aligns with job role.



## Step 1 — Identify Scheduled Task Creation

```
index="win-alert" EventCode=4698 AssessmentTaskOne
| table _time EventCode user_name host Task_Name Message
```

EventCode 4698 → Scheduled task created.

Only one event found → suspicious.



## Step 2 — Review Task Behaviour

Analysis of Message field shows:

- Uses **certutil** to download `rv.exe`
- Saved as `DataCollector.exe`
- Executed via PowerShell
- Runs daily

➡️ Persistence mechanism detected.

**Classification:** True Positive

Escalate to SOC L2.

---

## Investigation Answers

### 1. Process ID creating task

```
index="win-alert" EventCode=4698 AssessmentTaskOne
```

**Answer:** 5816



### 2. Parent process name

```
index="win-alert" ProcessId=4128
```

**Answer:** cmd.exe



### 3. Local group enumerated

```
index="win-alert" oliver.thompson (EventCode=4799 OR "net group" OR "net localgroup" OR "Get-LocalGroup")
| table _time EventCode CommandLine TargetUserName Group_Name
```

**Answer:** Administrators



### 4. Workstation used for login

```
index="win-alert" oliver.thompson EventCode=4624
| table _time Workstation_Name WorkstationName Source_Network_Address LogonType
```

**Answer:** DEV-QA-SERVER

---

# Web Shell Alert

## Alert Scenario

A web-based alert indicates possible web shell activity.

### Alert Details

- **Alert Name:** Potential Web Shell Upload Detected  
- **Time:** 14/09/2025 09:31:51 AM  
- **Resource:** http://web.trywinme.thm  
- **Suspicious IP:** 171.251.232.40  

Logs Location:

```
index=web-alert
```



## Step 1 — Review Activity

```
index=web-alert 171.251.232.40
| table _time clientip useragent uri_path method status
| sort + _time
```

### Findings

- Numerous requests detected.
- User-Agent identified as **Hydra**.
- Indicates brute-force attempts against `wp-login.php`.



## Step 2 — Investigate Web Shell Activity

Exclude Hydra traffic:

```
index=web-alert 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)"
| table _time clientip useragent uri_path referer referer_domain method status
```

Observation:

- POST request referencing `b374k.php`
- Strong web shell indicator.



## Step 3 — Analyse Web Shell Interaction

```
index=web-alert 171.251.232.40 b374k.php
| table _time clientip useragent uri_path referer referer_domain method status
| sort + _time
```

### Findings

- Successful interaction with web shell.
- Four POST requests executed.

Activity confirmed malicious.

**Classification:** True Positive  
Escalate to SOC Level 2.



## Investigation Answers

### 1. Hydra brute-force start time

**Answer:** 2025-09-14 21:20:27



### 2. Web shell user-agent

**Answer:**

Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36



### 3. Number of web shell requests

**Answer:** 4



# SOC Analyst Key Takeaways

- Always review alert context before opening SIEM.
- Validate source IP location.
- Identify attack success, not only attempts.
- Detect persistence mechanisms early.
- Escalate confirmed incidents promptly.
- Document investigation workflow clearly.

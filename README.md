# Splunk Analysis Projects

## Overview
This repository showcases **hands-on SOC and Incident Handling investigations performed using Splunk SIEM**.  
Each project focuses on analyzing real-world attack scenarios, correlating logs across multiple sources, and reconstructing attacker activity using SPL queries.

The goal of this repository is to demonstrate **practical SOC Analyst skills** such as:
- Log analysis
- Incident triage
- Threat detection
- Attack timeline reconstruction
- Cyber Kill Chain mapping

---

## Repository Structure

### 📁 [Incident Handling using Splunk](https://github.com/sarrah10/Splunk-Analysis/blob/main/Incident%20Handling%20using%20Splunk.md)
A complete **end-to-end incident handling case study** involving a **website defacement attack**.

This investigation includes:
- Initial alert identification
- Network and host log analysis
- Joomla admin brute-force detection
- Credential extraction using regex in SPL
- Malware execution confirmation via Sysmon logs
- Command-and-Control (C2) traffic identification
- Website defacement root cause analysis
- Mapping the attacker’s actions across **all 7 phases of the Cyber Kill Chain**

---

### 📁 [SPL queries in splunk](https://github.com/sarrah10/Splunk-Analysis/blob/main/SPL%20queries%20in%20splunk.md)
A curated collection of **Splunk SPL queries** used during investigations, including:
- Brute-force detection
- Suspicious POST request identification
- Field extraction using `rex`
- Time-based correlation
- Outbound connection analysis

These queries demonstrate **how raw logs are transformed into actionable evidence**.

---

### 📁 [vpn logs analysis using splunk siem](https://github.com/sarrah10/Splunk-Analysis/blob/main/vpn%20logs%20analysis%20using%20splunk%20siem.md)
A focused investigation on **VPN authentication logs**, covering:
- Detection of suspicious VPN connections
- Post-termination access analysis
- Identification of abnormal login behavior
- Time-window and user-based correlation

This analysis reflects **real SOC monitoring and alert validation workflows**.

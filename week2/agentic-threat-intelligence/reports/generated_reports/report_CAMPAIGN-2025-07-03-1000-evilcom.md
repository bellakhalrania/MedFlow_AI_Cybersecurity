# Threat Intelligence Report

**Campaign:** PowerShell C2 Download from Evil.com
**Campaign ID:** CAMPAIGN-2025-07-03-1000-evilcom
**Generated:** 2026-07-06T10:20:51.158767+00:00

---

<think>
Okay, let's start by understanding the user's query. They want me to generate a professional incident report in Markdown based on the provided data. The report needs to follow specific sections and adhere to certain guidelines. 

First, I'll go through each section one by one. The Executive Summary should be concise, highlighting the key points. The Incident Overview needs to present the main facts without extra details. The Timeline is straightforward with the given event.

For the Attack Chain, I need to break down the steps based on the event provided. The MITRE ATT&CK Mapping is already given with T1059.001, so I'll structure that into a table. The Vulnerability Analysis section is next, but since there are no vulnerabilities listed, I'll note that none were found.

The Indicators of Compromise (IOCs) are provided in a list, so I'll convert them into a table with the required columns. The Campaign Assessment and Risk Assessment need to be brief summaries based on the given campaign data. Predicted Next Steps are empty, so I'll mention that no predictions were made. 

Response Recommendations should be actionable steps, like isolating the host, reviewing logs, etc. The Confidence Assessment is based on the campaign's confidence level. 

I need to ensure that all sections are included and formatted correctly with tables where necessary. Also, I must avoid inventing any information beyond what's provided. Let me check each section again to make sure I didn't miss anything. The user emphasized conciseness and technical accuracy, so I'll keep the language professional but not overly complex. Finally, I'll review the word count to ensure it's under 500 words as requested.
</think>

# Incident Report: PowerShell C2 Download from Evil.com  

## Executive Summary  
An administrator account on `target-node2` executed a PowerShell command to download a malicious payload from a known C2 server (`evil.com`). The activity aligns with ATT&CK techniques and leverages suspicious network connections.  

---

## Incident Overview  
- **Host**: `target-node2`  
- **User**: `Administrator`  
- **Process**: `powershell.exe`  
- **Action**: Downloaded `payload.exe` from `http://evil.com/payload.exe`  
- **Source IP**: `185.220.101.45` (suspicious)  
- **Destination IP**: `192.168.1.28` (benign)  

---

## Timeline  
| Timestamp           | Event Type         | Host         | Description                              |  
|---------------------|--------------------|--------------|------------------------------------------|  
| 2025-07-03T10:00:00Z| Network Connection | `target-node2` | PowerShell initiated download of `payload.exe` from `evil.com` |  

---

## Attack Chain  
1. **Initial Compromise**: Administrator account compromised (unknown vector).  
2. **Command Execution**: PowerShell used to download `payload.exe` via `Invoke-WebRequest`.  
3. **C2 Communication**: Payload retrieved from malicious domain `evil.com` (IP: `185.220.101.45`).  

---

## MITRE ATT&CK Mapping  
| Technique ID       | Technique Name | Confidence | Description                              |  
|--------------------|----------------|------------|------------------------------------------|  
| T1059.001          | PowerShell    | 0.91       | PowerShell used to download malicious payload |  

---

## Vulnerability Analysis  
**No vulnerabilities identified**.  

---

## Indicators of Compromise  
| IOC Value              | Type         | Verdict      | Category           | Confidence |  
|------------------------|--------------|--------------|--------------------|------------|  
| `185.220.101.45`       | IP           | Suspicious   | C2 Server          | 0.7        |  
| `http://evil.com/payload.exe` | URL | Malicious    | Malware Distribution | 0.9      |  
| `evil.com`             | Domain       | Malicious    | Malicious Domain   | 0.85       |  
| `payload.exe`          | File Path    | Suspicious   | Malware            | 0.65       |  
| `powershell.exe`       | Process Name | Suspicious   | Command Interpreter| 0.6        |  

---

## Campaign Assessment  
**Campaign ID**: `CAMPAIGN-2025-07-03-1000-evilcom`  
Single-event campaign leveraging PowerShell to download a malicious payload from a known C2 server. High confidence in malicious intent due to suspicious domain, executable filename, and administrative privileges.  

---

## Risk Assessment  
| Impact | Likelihood |  
|--------|------------|  
| High   | Medium     |  

---

## Predicted Next Steps  
**No predictions available**.  

---

## Response Recommendations  
1. **Isolate `target-node2`** from the network to prevent lateral movement.  
2. **Review logs** for additional PowerShell activity by the `Administrator` account.  
3. **Block `evil.com` and `185.220.101.45`** in firewalls and DNS filters.  
4. **Investigate credential compromise** (e.g., password reuse, phishing).  

---

## Confidence Assessment  
**Overall Confidence**: 82% (based on campaign analysis and IOC alignment).
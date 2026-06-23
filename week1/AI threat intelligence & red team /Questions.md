Red Team Agent

Should retrieve ATT&CK techniques and procedures.

How does Ryuk maintain persistence on Windows systems?
What techniques are commonly used for credential dumping?
Explain technique T1003.
How do attackers abuse PowerShell for execution?
What ATT&CK techniques are associated with lateral movement?
Describe the procedure used by adversaries for Remote Services.
How is PsExec used by attackers?
What are common defense evasion techniques used by ransomware groups?
Invalid ID Test (Guardrail)
Explain technique T9999.
What does T12345 describe?

Expected: Refusal / Invalid MITRE ID

🔵 CTI Analyst Agent

Should focus on threat intelligence and healthcare context.

Which APT groups target healthcare organizations?
What techniques are frequently used in healthcare ransomware campaigns?
Analyze the threat posed by Ryuk to hospitals.
Which ATT&CK tactics are most relevant to healthcare breaches?
Compare WannaCry and Ryuk from a CTI perspective.
What are the top ATT&CK techniques observed in recent healthcare attacks?
🟣 Attribution Agent

Should retrieve actors, malware, tools, and confidence scores.

Which actors use Mimikatz?
Which threat groups use PsExec and Mimikatz together?
Who is known to use Cobalt Strike?
What malware is associated with APT29?
Which groups have used Empire?
What tools are linked to FIN7?
Identify actors associated with T1003.
Hallucination Test
Which actor uses the malware SuperHacker9000?

Expected: No evidence found, not a fabricated answer.

🟢 Detection Agent

Should focus on detections and mitigations.

How can I detect credential dumping?
What logs help identify PowerShell abuse?
How would you detect T1055 Process Injection?
What mitigations exist for T1003?
Detect suspicious use of PsExec.
What Windows Event IDs are useful for detecting lateral movement?
How can defenders identify Cobalt Strike activity?
🟡 Routing Tests

These verify that the orchestrator chooses the correct agent.

Query	Expected Agent
How does Ryuk gain persistence?	Red Team
Which actors use Mimikatz?	Attribution
Detect PowerShell abuse	Detection
Which APT groups target healthcare?	CTI
Explain T1055	Red Team
How can I detect T1055?	Detection
🔥 Stress Tests
Compare T1003, T1055, and T1021.
Which actors use T1003 and how can I detect it?
Explain Ryuk persistence and provide mitigations.
Which healthcare-focused groups use credential dumping techniques?
Detect activity associated with actors using PsExec.

These multi-part questions test retrieval, routing, grounding, and source ranking simultaneously.

🚨 Critical Tests Before Demo

Ask these 5:

What is T1047?
What is T9999?
Which actors use Mimikatz and PsExec together?
How can I detect credential dumping?
Which APT groups target healthcare?
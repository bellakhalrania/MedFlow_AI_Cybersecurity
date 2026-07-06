#!/usr/bin/env python3
"""
Test script to debug response agent LLM calls.
"""

from agents.response_agent import ResponseAgent
from config import config

# Test data matching the user's scenario
campaign = {
    "campaign_id": "CAMPAIGN-2025-07-03-1",
    "confidence": 0.7,
    "name": "PowerShell Download Attack",
    "related_techniques": [
        {
            "confidence": 0.91,
            "name": "PowerShell",
            "technique_id": "T1059.001"
        }
    ],
    "summary": "Single-event campaign involving PowerShell execution to download a malicious payload from a suspicious external IP to an internal host."
}

techniques = [
    {
        "confidence": 0.91,
        "evidence_event_id": None,
        "name": "PowerShell",
        "reason": "PowerShell process executed with Invoke-WebRequest to download a suspicious payload from a known malicious URL (http://evil.com/payload.exe).",
        "technique_id": "T1059.001"
    }
]

iocs = [
    {
        "category": "network",
        "confidence": 0.6,
        "ioc_type": "ip",
        "justification": "Public IP address not associated with known benign infrastructure; requires further contextual analysis",
        "value": "185.220.101.45",
        "verdict": "suspicious"
    },
    {
        "category": "network",
        "confidence": 1.0,
        "ioc_type": "ip",
        "justification": "Private IPv4 address within reserved range (RFC 1918) used for internal networks",
        "value": "192.168.159.128",
        "verdict": "benign"
    },
    {
        "category": "network",
        "confidence": 0.9,
        "ioc_type": "url",
        "justification": "URL contains known malicious domain 'evil.com' and executable payload filename",
        "value": "http://evil.com/payload.exe",
        "verdict": "malicious"
    },
    {
        "category": "host",
        "confidence": 0.7,
        "ioc_type": "process_name",
        "justification": "Common Windows utility often abused by attackers for command execution",
        "value": "powershell.exe",
        "verdict": "suspicious"
    },
    {
        "category": "network",
        "confidence": 0.95,
        "ioc_type": "domain",
        "justification": "Domain name associated with malicious activity based on context",
        "value": "evil.com",
        "verdict": "malicious"
    }
]

print("Testing Response Agent...")
print(f"Campaign: {campaign.get('name')}")
print(f"Techniques: {len(techniques)}")
print(f"IOCs: {len(iocs)}")
print(f"DRY_RUN: {config.DRY_RUN}")
print(f"AUTO_RESPONSE_ENABLED: {config.AUTO_RESPONSE_ENABLED}")
print()

agent = ResponseAgent()
results = agent.run(campaign, techniques, iocs)

print(f"Actions generated: {len(results)}")
print()

for i, result in enumerate(results, 1):
    print(f"Action {i}:")
    print(f"  Type: {result.action.action_type}")
    print(f"  Target: {result.action.target}")
    print(f"  Severity: {result.action.severity}")
    print(f"  Confidence: {result.action.confidence}")
    print(f"  Status: {result.status}")
    print(f"  Detail: {result.detail}")
    print(f"  Dry Run: {result.dry_run}")
    print()

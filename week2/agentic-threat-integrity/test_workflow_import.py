#!/usr/bin/env python3
"""Test script to verify workflow has vulnerability node."""

import sys
sys.path.insert(0, '/home/rania/Documents/MedFlow_AI_Cybersecurity/week2/agentic-threat-intelligence')

from graph.workflow import threat_intel_workflow

print("Testing workflow import...")
print(f"Workflow nodes: {threat_intel_workflow.nodes}")
print(f"Workflow edges: {threat_intel_workflow.edges}")

# Check if vulnerability node exists
if "vulnerability" in threat_intel_workflow.nodes:
    print("✓ Vulnerability node exists in workflow")
else:
    print("✗ Vulnerability node NOT found in workflow")
    print(f"Available nodes: {list(threat_intel_workflow.nodes.keys())}")

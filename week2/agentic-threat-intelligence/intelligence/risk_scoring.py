from typing import List, Dict


def score_campaign(techniques: List[Dict], iocs: List[Dict]) -> str:
    malicious_iocs = sum(1 for i in iocs if i.get("verdict") == "malicious")
    high_confidence_techniques = sum(1 for t in techniques if t.get("confidence", 0) >= 0.7)

    score = malicious_iocs * 2 + high_confidence_techniques

    if score >= 8:
        return "Critical"
    elif score >= 5:
        return "High"
    elif score >= 2:
        return "Medium"
    return "Low"

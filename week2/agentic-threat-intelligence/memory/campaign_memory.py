"""
memory/campaign_memory.py
Tracks known/ongoing campaigns across investigation runs so the
Correlation Agent can recognize when new events belong to a campaign seen
in a previous run, rather than always creating a new one.
"""

from typing import Dict, Optional
from memory.investigation_memory import investigation_memory


def find_matching_campaign(related_techniques: list[str]) -> Optional[Dict]:
    """Naive overlap-based match against campaigns seen in recent runs."""
    related_set = set(related_techniques)
    for record in reversed(investigation_memory.recent(20)):
        campaign = record.get("campaign", {})
        existing_techniques = set(campaign.get("related_techniques", []))
        if existing_techniques and len(existing_techniques & related_set) >= 2:
            return campaign
    return None

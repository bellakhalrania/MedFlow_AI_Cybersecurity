"""
reports/report_generator.py
Saves the final markdown report to disk under reports/generated_reports/.
"""

import os
from datetime import datetime, timezone
from typing import Dict
from config import config
from reports.markdown_templates import render_report


def save_report(body: str, campaign: Dict) -> str:
    os.makedirs(config.REPORTS_OUTPUT_DIR, exist_ok=True)

    campaign_id = campaign.get("campaign_id", "unknown")
    campaign_name = campaign.get("name", "Unclassified Activity")
    generated_at = datetime.now(timezone.utc).isoformat()

    full_report = render_report(body, campaign_name, campaign_id, generated_at)

    filename = f"report_{campaign_id}.md"
    filepath = os.path.join(config.REPORTS_OUTPUT_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(full_report)

    return filepath

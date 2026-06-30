from jinja2 import Template

REPORT_TEMPLATE = Template("""\
# Threat Intelligence Report

**Campaign:** {{ campaign_name }}
**Campaign ID:** {{ campaign_id }}
**Generated:** {{ generated_at }}

---

{{ body }}
""")


def render_report(body: str, campaign_name: str, campaign_id: str, generated_at: str) -> str:
    return REPORT_TEMPLATE.render(
        body=body,
        campaign_name=campaign_name,
        campaign_id=campaign_id,
        generated_at=generated_at,
    )

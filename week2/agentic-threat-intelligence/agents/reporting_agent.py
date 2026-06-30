from graph.state import InvestigationState
from llm.groq_client import invoke_llm
from llm.prompts import REPORTING_SYSTEM_PROMPT
from reports.report_generator import save_report


class ReportingAgent:
    def run(self, state: InvestigationState) -> str:
        prompt = (
            f"Events:\n{state.get('events')}\n\n"
            f"IOCs:\n{state.get('iocs')}\n\n"
            f"ATT&CK Techniques:\n{state.get('techniques')}\n\n"
            f"Campaign:\n{state.get('campaign')}\n\n"
            f"Prediction:\n{state.get('prediction')}"
        )
        report_markdown = invoke_llm(system_prompt=REPORTING_SYSTEM_PROMPT, user_prompt=prompt)
        save_report(report_markdown, campaign=state.get("campaign", {}))
        return report_markdown

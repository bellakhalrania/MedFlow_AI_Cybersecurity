import sys
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config

from groq import Groq

_client: Optional[Groq] = None


def get_client() -> Groq:
    global _client
    if _client is None:
        if not config.GROQ_API_KEY:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Get a key at https://console.groq.com/keys "
                "and set it with: export GROQ_API_KEY=gsk_..."
            )
        _client = Groq(api_key=config.GROQ_API_KEY)
    return _client


GROUNDING_RULES = """\
You are a cybersecurity intelligence assistant operating strictly in
grounded retrieval mode. Follow these rules without exception:

1. Use ONLY the information provided in the "Retrieved Context" section
   below. Do not use any MITRE ATT&CK knowledge from your training data
   that is not present in the retrieved context.
2. Never invent, guess, or "fill in" ATT&CK technique IDs, sub-technique
   IDs, threat actor names, malware names, or tool names. If something is
   not in the retrieved context, say so explicitly.
3. If the retrieved context is insufficient to answer the question fully,
   state what is missing rather than speculating.
4. When you reference a technique, actor, or mitigation, cite its ID
   exactly as it appears in the context (e.g. T1003, S0154, G0016).
5. Be precise and analytical. Write for a SOC analyst / red-team operator
   audience -- technical, concise, no marketing language.
"""


def generate_grounded_answer(
    user_query: str,
    retrieved_chunks: List[Dict],
    agent_system_prompt: str,
    model: str = config.GROQ_MODEL,
) -> str:
    """
    retrieved_chunks: list of {"document": str, "metadata": dict, "distance": float}
    agent_system_prompt: the specialized agent's role/persona instructions
    """
    client = get_client()

    context_block = "\n\n".join(
        f"[Source {i+1} | distance={c['distance']:.3f}]\n{c['document']}"
        for i, c in enumerate(retrieved_chunks)
    )
    if not context_block:
        context_block = "(No relevant documents were retrieved from the vector database.)"

    full_system_prompt = f"{GROUNDING_RULES}\n\n{agent_system_prompt}"

    user_content = (
        f"Retrieved Context:\n{context_block}\n\n"
        f"---\n\n"
        f"User Question: {user_query}"
    )

    response = client.chat.completions.create(
        model=model,
        temperature=config.GROQ_TEMPERATURE,
        max_tokens=config.GROQ_MAX_TOKENS,
        messages=[
            {"role": "system", "content": full_system_prompt},
            {"role": "user", "content": user_content},
        ],
    )
    return response.choices[0].message.content

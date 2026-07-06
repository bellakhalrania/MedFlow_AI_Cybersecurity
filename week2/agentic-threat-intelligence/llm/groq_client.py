
from langchain_groq import ChatGroq
from config import config

llm = ChatGroq(
    api_key=config.GROQ_API_KEY,
    model=config.GROQ_MODEL,
    temperature=config.GROQ_TEMPERATURE,
)


def invoke_llm(system_prompt: str, user_prompt: str) -> str:
    """Convenience wrapper for a single-turn system+user call."""
    messages = [
        ("system", system_prompt),
        ("human", user_prompt),
    ]
    response = llm.invoke(messages)
    return response.content

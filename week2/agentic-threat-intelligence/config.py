"""
config.py
Central configuration for the Agentic Threat Intelligence Platform.
All values are loaded from environment variables (.env file) so secrets
never live in source control.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ---------------- Groq LLM ----------------
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    GROQ_TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.1"))

    # ---------------- ChromaDB ----------------
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./data/chroma_store")
    CHROMA_COLLECTION_ATTACK = os.getenv("CHROMA_COLLECTION_ATTACK", "attack_techniques")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

    # ---------------- Neo4j ----------------
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "changeme")

    # ---------------- MITRE ATT&CK data ----------------
    ATTACK_DATA_PATH = os.getenv(
        "ATTACK_DATA_PATH", "./data/attack_data/enterprise_attack.json"
    )

    # ---------------- Telemetry inputs ----------------
    RAW_LOGS_DIR = os.getenv("RAW_LOGS_DIR", "./data/raw_logs")
    SAMPLE_EVENTS_DIR = os.getenv("SAMPLE_EVENTS_DIR", "./data/sample_events")

    # ---------------- Reporting ----------------
    REPORTS_OUTPUT_DIR = os.getenv("REPORTS_OUTPUT_DIR", "./reports/generated_reports")

    @classmethod
    def validate(cls):
        missing = []
        if not cls.GROQ_API_KEY:
            missing.append("GROQ_API_KEY")
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}. "
                f"Copy .env.example to .env and fill in the values."
            )


config = Config()

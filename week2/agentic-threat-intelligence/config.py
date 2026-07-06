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

    # ---------------- Response / Action layer ----------------
    # Global kill switch. Default OFF: every action requires human approval
    # until you've tested the policy and connectors and explicitly opt in.
    AUTO_RESPONSE_ENABLED = os.getenv("AUTO_RESPONSE_ENABLED", "false").lower() == "true"

    # Dry run: when true, connectors log what they WOULD do instead of
    # calling the real firewall/EDR/IAM API. Keep this true until connectors
    # are wired to your real infrastructure and you trust the policy.
    DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

    # ---------------- Logging ----------------
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # ---------------- HTTP (shared by all outbound connectors) ----------------
    API_TIMEOUT = int(os.getenv("API_TIMEOUT", "10"))
    API_RETRY = int(os.getenv("API_RETRY", "3"))

    # ---------------- Slack ----------------
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

    # ---------------- Firewall ----------------
    FIREWALL_API_URL = os.getenv("FIREWALL_API_URL", "")
    FIREWALL_API_TOKEN = os.getenv("FIREWALL_API_TOKEN", "")

    # ---------------- Wazuh ----------------
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "")
    WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "")
    WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")

    # ---------------- Azure AD / Entra ID ----------------
    AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
    AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
    AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")

    # ---------------- Okta ----------------
    OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "")
    OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN", "")

    # ---------------- CrowdStrike ----------------
    CROWDSTRIKE_API_URL = os.getenv("CROWDSTRIKE_API_URL", "")
    CROWDSTRIKE_CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID", "")
    CROWDSTRIKE_CLIENT_SECRET = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")

    # ---------------- SentinelOne ----------------
    SENTINELONE_API_URL = os.getenv("SENTINELONE_API_URL", "")
    SENTINELONE_API_TOKEN = os.getenv("SENTINELONE_API_TOKEN", "")

    @classmethod
    def validate(cls):
        missing = []

        # Always required
        if not cls.GROQ_API_KEY:
            missing.append("GROQ_API_KEY")

        # Only required once real automated actions are enabled.
        # Keeps the project runnable in dry/manual mode without
        # forcing you to configure connectors you're not using yet.
        if cls.AUTO_RESPONSE_ENABLED:
            if not cls.SLACK_WEBHOOK_URL:
                missing.append("SLACK_WEBHOOK_URL")

            if not cls.FIREWALL_API_URL:
                missing.append("FIREWALL_API_URL")

            if not cls.FIREWALL_API_TOKEN:
                missing.append("FIREWALL_API_TOKEN")

            if not cls.WAZUH_API_URL:
                missing.append("WAZUH_API_URL")

            if not cls.WAZUH_USERNAME:
                missing.append("WAZUH_USERNAME")

            if not cls.WAZUH_PASSWORD:
                missing.append("WAZUH_PASSWORD")

        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}. "
                f"Copy .env.example to .env and fill in the values."
            )


config = Config()
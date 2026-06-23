import os
import re
from pathlib import Path

from dotenv import load_dotenv

#this file contains all the configuration variables for the project, such as paths, model names, and API keys. It loads environment variables from a .env file and defines constants that will be used throughout the codebase.
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATA_DIR = BASE_DIR / "data"
STORAGE_DIR = BASE_DIR / "storage"
CHROMA_DIR = STORAGE_DIR / "chroma_db"

MITRE_BUNDLE_PATH = DATA_DIR / "enterprise-attack.json"
MITRE_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

PARSED_DATASETS_DIR = DATA_DIR / "parsed"


EMBEDDING_MODEL_NAME = "BAAI/bge-base-en-v1.5"
EMBEDDING_DIM = 768


BGE_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "



COLLECTION_ATTACK = "attack_db"        # techniques / sub-techniques
COLLECTION_REDTEAM = "redteam_db"      # "uses" relationships (procedures)
COLLECTION_ACTOR = "actor_db"          # intrusion-sets, malware, tools
COLLECTION_DETECTION = "detection_db"  # mitigations, analytics, detection strategies

ALL_COLLECTIONS = [
    COLLECTION_ATTACK,
    COLLECTION_REDTEAM,
    COLLECTION_ACTOR,
    COLLECTION_DETECTION,
]

# How many chunks to retrieve per query, per collection
TOP_K_RETRIEVAL = 6


GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

GROQ_MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3-32b")
GROQ_TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.2"))
GROQ_MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "1200"))


# Matches T1003, T1003.001, TA0001, S0154 (software), G0016 (group), M1015 (mitigation)
MITRE_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?|TA\d{4}|S\d{4}|G\d{4}|M\d{4})\b")

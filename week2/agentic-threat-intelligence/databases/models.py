"""
databases/models.py
Shared Pydantic models used across agents and databases for type safety.
"""

from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class NormalizedEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    raw_source: Optional[str] = None


class EnrichedIOC(BaseModel):
    value: str
    ioc_type: str  # ip | domain | hash | url
    verdict: str   # benign | suspicious | malicious
    category: Optional[str] = None
    justification: Optional[str] = None


class MappedTechnique(BaseModel):
    technique_id: str
    name: str
    confidence: float
    evidence_event_id: Optional[str] = None


class Campaign(BaseModel):
    campaign_id: str
    name: str
    timeline: List[Dict[str, Any]] = []
    related_techniques: List[str] = []


class Prediction(BaseModel):
    likely_next_techniques: List[str] = []
    rationale: str = ""

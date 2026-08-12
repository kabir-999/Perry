import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    category: str
    severity: str
    confidence: str
    url: str
    method: str
    parameter: str
    evidence: str
    request_summary: str
    response_summary: str
    description: str
    impact: str
    remediation: str
    risk_score: float
    llm_verdict: Optional[str] = None
    llm_confidence: Optional[float] = None
    llm_explanation: Optional[str] = None
    llm_false_positive_reason: Optional[str] = None
    created_at: datetime

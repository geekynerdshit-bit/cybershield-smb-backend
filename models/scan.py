from pydantic import BaseModel, validator
from typing import Optional, List
from datetime import datetime

class ScanRequest(BaseModel):
    url: str

    @validator("url")
    def clean_url(cls, v):
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

class Finding(BaseModel):
    title: str
    severity: str  # critical | warning | good
    plain_explanation: str
    fix_steps: List[str]

class ScanReport(BaseModel):
    overall_severity: str
    summary: str
    score: int
    findings: List[Finding]
    top_priority: str

class ScanResponse(BaseModel):
    scan_id: str
    url: str
    status: str  # completed | error
    report: Optional[ScanReport]
    raw_results: Optional[dict]
    scanned_at: datetime
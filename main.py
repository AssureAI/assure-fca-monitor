from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Literal, Optional
from datetime import datetime
import re
import os
import hmac
import hashlib

# --------------------------------------------------
# APP SETUP
# --------------------------------------------------

app = FastAPI(title="Assure Deterministic Compliance Engine")

# --------------------------------------------------
# OPTIONAL AUTH (recommended)
# --------------------------------------------------

INGEST_TOKEN = os.environ.get("INGEST_TOKEN")  # shared secret with Base44

def verify_hmac(request: Request, body: bytes):
    if not INGEST_TOKEN:
        return  # auth disabled if not set

    signature = request.headers.get("X-Signature")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")

    expected = hmac.new(
        INGEST_TOKEN.encode("utf-8"),
        body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")

# --------------------------------------------------
# MODELS (STRICT CONTRACT)
# --------------------------------------------------

Status = Literal["OK", "POTENTIAL_ISSUE", "NOT_ASSESSED"]

class CheckRequest(BaseModel):
    advice_type: str = Field(..., description="advised / execution_only / standard")
    filename: Optional[str] = None
    document_text: str = Field(..., min_length=1)

class RuleResult(BaseModel):
    rule_id: str
    status: Status
    citation: str
    source_url: str
    excerpt: Optional[str] = None  # keep null in v1

class CheckResponse(BaseModel):
    ruleset_version: str
    checked_at: str
    summary: Dict[str, int]
    results: List[RuleResult]

# --------------------------------------------------
# RULESET
# --------------------------------------------------

RULESET_VERSION = "cobs-sr-v0.1"

def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()

def contains_any(text: str, phrases: List[str]) -> bool:
    t = normalize(text)
    return any(normalize(p) in t for p in phrases)

def run_rules(advice_type: str, text: str) -> List[RuleResult]:
    at = (advice_type or "").lower().strip()
    results: List[RuleResult] = []

    results.append(RuleResult(
        rule_id="SR_RISK_PROFILE_PRESENT",
        status="OK" if contains_any(text, [
            "risk profile", "attitude to risk", "risk questionnaire"
        ]) else "POTENTIAL_ISSUE",
        citation="COBS 9.2.2R",
        source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
        excerpt=None
    ))

    results.append(RuleResult(
        rule_id="SR_CAPACITY_FOR_LOSS_PRESENT",
        status="OK" if contains_any(text, [
            "capacity for loss", "loss capacity"
        ]) else "POTENTIAL_ISSUE",
        citation="COBS 9.2.2R",
        source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
        excerpt=None
    ))

    results.append(RuleResult(
        rule_id="SR_COSTS_CHARGES_PRESENT",
        status="OK" if contains_any(text, [
            "cost", "charge", "fee", "ongoing charges", "ocf"
        ]) else "POTENTIAL_ISSUE",
        citation="COBS 6.1ZA / 6.1ZB",
        source_url="https://handbook.fca.org.uk/handbook/COBS/6/",
        excerpt=None
    ))

    if at in ("advised", "standard", "financial_advice"):
        status = "OK" if contains_any(text, [
            "we recommend", "our recommendation", "suitable", "suitability"
        ]) else "POTENTIAL_ISSUE"
    else:
        status = "NOT_ASSESSED"

    results.append(RuleResult(
        rule_id="SR_SUITABILITY_RECOMMENDATION_PRESENT",
        status=status,
        citation="COBS 9.2.1R",
        source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
        excerpt=None
    ))

    results.append(RuleResult(
        rule_id="SR_CLIENT_OBJECTIVES_PRESENT",
        status="OK" if contains_any(text, [
            "objectives", "goals", "needs", "your objective", "your objectives"
        ]) else "POTENTIAL_ISSUE",
        citation="COBS 9.2.2R",
        source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
        excerpt=None
    ))

    return results

# --------------------------------------------------
# ROUTES
# --------------------------------------------------

@app.post("/check", response_model=CheckResponse)
async def check(request: Request, payload: CheckRequest):
    body = await request.body()
    verify_hmac(request, body)

    results = run_rules(payload.advice_type, payload.document_text)

    summary = {
        "ok": sum(1 for r in results if r.status == "OK"),
        "potential_issue": sum(1 for r in results if r.status == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r.status == "NOT_ASSESSED"),
    }

    resp = CheckResponse(
        ruleset_version=RULESET_VERSION,
        checked_at=datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        summary=summary,
        results=results,
    )
    return JSONResponse(resp.model_dump())

@app.get("/health")
def health():
    return {"status": "ok"}

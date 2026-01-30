from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Optional
import os
import hmac
import hashlib

from executor import run_rules_engine

# --------------------------------------------------
# APP SETUP
# --------------------------------------------------

app = FastAPI(title="Assure Deterministic Compliance Engine")

# --------------------------------------------------
# OPTIONAL AUTH (recommended)
# --------------------------------------------------

INGEST_TOKEN = os.environ.get("INGEST_TOKEN")  # shared secret with Base44

def verify_hmac(request: Request, body: bytes):
    """
    If INGEST_TOKEN is set, require callers to provide:
      X-Signature: hex(hmac_sha256(INGEST_TOKEN, raw_request_body))
    """
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
# REQUEST MODEL (STRICT INPUT CONTRACT)
# --------------------------------------------------

class CheckRequest(BaseModel):
    advice_type: str = Field(..., description="e.g. advised / execution_only / standard")
    filename: Optional[str] = None
    document_text: str = Field(..., min_length=1)

    # Optional context flags you can start using immediately (or later)
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False

# --------------------------------------------------
# ROUTES
# --------------------------------------------------

@app.post("/check")
async def check(request: Request, payload: CheckRequest):
    # Verify signature using the exact raw body that was sent
    raw_body = await request.body()
    verify_hmac(request, raw_body)

    # Build context for YAML rules applicability
    context: Dict[str, object] = {
        "advice_type": payload.advice_type,
        "investment_element": bool(payload.investment_element),
        "ongoing_service": bool(payload.ongoing_service),
    }

    out = run_rules_engine(
        document_text=payload.document_text,
        context=context
        # rules_path left as default inside executor.py
    )

    return JSONResponse(out)

@app.get("/health")
def health():
    return {"status": "ok"}

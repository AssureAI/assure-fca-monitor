from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
from typing import Dict, Optional
from datetime import datetime
import os
import hmac
import hashlib
import json

from executor import run_rules_engine

# --------------------------------------------------
# APP SETUP
# --------------------------------------------------

app = FastAPI(title="Assure Deterministic Compliance Engine")

# --------------------------------------------------
# OPTIONAL AUTH (recommended)
# --------------------------------------------------

INGEST_TOKEN = os.environ.get("INGEST_TOKEN")

def verify_hmac(request: Request, body: bytes):
    if not INGEST_TOKEN:
        return

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
# INPUT MODEL
# --------------------------------------------------

class CheckRequest(BaseModel):
    advice_type: str = Field(..., description="advised / execution_only / standard")
    document_text: str = Field(..., min_length=1)
    investment_element: bool = True
    ongoing_service: bool = False

# --------------------------------------------------
# CORE ENGINE ROUTE (PRODUCTION)
# --------------------------------------------------

@app.post("/check")
async def check(request: Request, payload: CheckRequest):
    raw_body = await request.body()
    verify_hmac(request, raw_body)

    context = {
        "advice_type": payload.advice_type,
        "investment_element": payload.investment_element,
        "ongoing_service": payload.ongoing_service,
    }

    result = run_rules_engine(
        document_text=payload.document_text,
        context=context,
        rules_path="rules/cobs-suitability-v1.yaml"
    )

    return JSONResponse(result)

# --------------------------------------------------
# ADMIN TEST UI
# --------------------------------------------------

@app.get("/admin/test", response_class=HTMLResponse)
def admin_test_page():
    return """
<!doctype html>
<html>
<head>
  <title>Assure Admin Test</title>
  <style>
    body { font-family: Arial; margin: 24px; max-width: 1100px; }
    textarea { width: 100%; height: 280px; font-family: monospace; }
    select, button { padding: 8px; margin-right: 10px; }
    pre { background: #0b1020; color: #e5e7eb; padding: 12px; border-radius: 8px; }
  </style>
</head>
<body>

<h1>Assure Admin Test</h1>

<label>Advice type</label>
<select id="advice_type">
  <option value="advised">advised</option>
  <option value="execution_only">execution_only</option>
  <option value="standard">standard</option>
</select>

<label>Investment element</label>
<select id="investment_element">
  <option value="true">true</option>
  <option value="false">false</option>
</select>

<label>Ongoing service</label>
<select id="ongoing_service">
  <option value="false">false</option>
  <option value="true">true</option>
</select>

<br/><br/>

<textarea id="document_text" placeholder="Paste SR text here..."></textarea>

<br/><br/>

<button onclick="runCheck()">Run check</button>

<h2>Result</h2>
<pre id="output">—</pre>

<script>
async function runCheck() {
  const payload = {
    advice_type: document.getElementById("advice_type").value,
    investment_element: document.getElementById("investment_element").value === "true",
    ongoing_service: document.getElementById("ongoing_service").value === "true",
    document_text: document.getElementById("document_text").value
  };

  const res = await fetch("/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const text = await res.text();
  document.getElementById("output").textContent = text;
}
</script>

</body>
</html>
"""

# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}

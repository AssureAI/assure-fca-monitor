from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
from typing import Dict, Optional
import os
import hmac
import hashlib
import json
import requests

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
    If INGEST_TOKEN is set, callers must provide:
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

    # Optional applicability flags (match YAML applies_when keys)
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False

# --------------------------------------------------
# CORE ENGINE ROUTE
# --------------------------------------------------

@app.post("/check")
async def check(request: Request, payload: CheckRequest):
    raw_body = await request.body()
    verify_hmac(request, raw_body)

    context: Dict[str, object] = {
        "advice_type": payload.advice_type,
        "investment_element": bool(payload.investment_element),
        "ongoing_service": bool(payload.ongoing_service),
    }

    out = run_rules_engine(
        document_text=payload.document_text,
        context=context,
        rules_path="rules/cobs-suitability-v1.yaml"
    )

    return JSONResponse(out)

# --------------------------------------------------
# ADMIN TEST PAGE (uses /check internally)
# --------------------------------------------------

@app.get("/admin/test", response_class=HTMLResponse)
def admin_test_page():
    return """
    <html>
      <head>
        <title>Assure Admin Test</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body { font-family: Arial, sans-serif; margin: 24px; max-width: 1100px; }
          textarea { width: 100%; height: 280px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
          input, select { padding: 8px; }
          .row { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; margin: 10px 0; }
          .card { border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-top: 16px; }
          .muted { color: #666; }
          .btn { padding: 10px 14px; border: 0; border-radius: 8px; background: #111827; color: #fff; cursor: pointer; }
          .btn:hover { opacity: 0.92; }
          label { font-weight: 700; }
        </style>
      </head>
      <body>
        <h1>Assure Admin Test</h1>
        <p class="muted">
          This page runs the engine by calling <code>POST /check</code> internally (same route a real client uses).
          Your INGEST_TOKEN is never exposed to the browser.
        </p>

        <form method="post" action="/admin/test">
          <div class="row">
            <div>
              <label>Advice type</label><br/>
              <select name="advice_type">
                <option value="advised" selected>advised</option>
                <option value="execution_only">execution_only</option>
                <option value="standard">standard</option>
              </select>
            </div>

            <div>
              <label>Investment element</label><br/>
              <select name="investment_element">
                <option value="true" selected>true</option>
                <option value="false">false</option>
              </select>
            </div>

            <div>
              <label>Ongoing service</label><br/>
              <select name="ongoing_service">
                <option value="false" selected>false</option>
                <option value="true">true</option>
              </select>
            </div>
          </div>

          <div class="row">
            <div style="flex: 1;">
              <label>Suitability Report text</label><br/>
              <textarea name="document_text" placeholder="Paste SR text here..."></textarea>
            </div>
          </div>

          <div class="row">
            <button class="btn" type="submit">Run check</button>
          </div>
        </form>
      </body>
    </html>
    """

@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_run(
    request: Request,
    advice_type: str = Form(...),
    investment_element: str = Form("true"),
    ongoing_service: str = Form("false"),
    document_text: str = Form(...),
):
    inv = True if (investment_element or "").lower() == "true" else False
    ong = True if (ongoing_service or "").lower() == "true" else False

    payload = {
        "advice_type": advice_type,
        "document_text": document_text,
        "investment_element": inv,
        "ongoing_service": ong,
    }

    body_bytes = json.dumps(payload).encode("utf-8")

    # Build URL to our own /check endpoint
    base = str(request.base_url).rstrip("/")
    check_url = base + "/check"

    headers = {"Content-Type": "application/json"}

    # If HMAC enabled, sign internally (browser never sees secret)
    if INGEST_TOKEN:
        sig = hmac.new(INGEST_TOKEN.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        headers["X-Signature"] = sig

    try:
        r = requests.post(check_url, data=body_bytes, headers=headers, timeout=30)
        status_code = r.status_code
        text = r.text
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else None
    except Exception as e:
        return HTMLResponse(f"<h1>Admin test failed</h1><pre>{str(e)}</pre>", status_code=500)

    if status_code != 200 or not isinstance(data, dict):
        return HTMLResponse(
            f"""
            <html><body style="font-family:Arial;margin:24px;max-width:1100px;">
              <h1>Admin test got error from /check</h1>
              <p><strong>Status:</strong> {status_code}</p>
              <pre style="background:#f7f7f7;padding:12px;border-radius:8px;overflow:auto;">{text}</pre>
              <p><a href="/admin/test">Back</a></p>
            </body></html>
            """,
            status_code=200
        )

    # Render results table
    def cls(st: str) -> str:
        if st == "OK":
            return "ok"
        if st == "POTENTIAL_ISSUE":
            return "pi"
        return "na"

    rows_html = ""
    for item in data.get("results", []):
        st = item.get("status", "")
        rows_html += f"""
          <tr>
            <td>{item.get("rule_id","")}</td>
            <td class="{cls(st)}">{st}</td>
            <td>{item.get("citation","")}</td>
            <td><a href="{item.get("source_url","")}" target="_blank">{item.get("source_url","")}</a></td>
          </tr>
        """

    pretty = json.dumps(data, indent=2)

    return f"""
    <html>
      <head>
        <title>Assure Admin Test Results</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body {{ font-family: Arial, sans-serif; margin: 24px; max-width: 1100px; }}
          .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-top: 16px; }}
          table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
          th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
          th {{ background: #f5f5f5; }}
          .ok {{ color: #0a7b34; font-weight: bold; }}
          .pi {{ color: #b26a00; font-weight: bold; }}
          .na {{ color: #666; font-weight: bold; }}
          pre {{ background: #0b1020; color: #e5e7eb; padding: 12px; border-radius: 10px; overflow: auto; }}
          a {{ color: #2563eb; }}
        </style>
      </head>
      <body>
        <h1>Results</h1>
        <p><a href="/admin/test">Run another</a></p>

        <div class="card">
          <h2>Summary</h2>
          <pre>{json.dumps(data.get("summary", {}), indent=2)}</pre>
          <p><strong>Ruleset:</strong> {data.get("ruleset_id","")} v{data.get("ruleset_version","")}</p>
          <p><strong>Checked at:</strong> {data.get("checked_at","")}</p>
        </div>

        <div class="card">
          <h2>Rule results</h2>
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Status</th>
                <th>Citation</th>
                <th>Source URL</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>

        <div class="card">
          <h2>Raw JSON</h2>
          <pre>{pretty}</pre>
        </div>
      </body>
    </html>
    """

# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from starlette.templating import Jinja2Templates

from executor import run_rules_engine
from database import SessionLocal, init_db, Run

app = FastAPI(title="Assure Deterministic Compliance Engine")
templates = Jinja2Templates(directory="templates")


@app.on_event("startup")
def _startup():
    init_db()


# -------------------------
# API MODEL
# -------------------------

class CheckRequest(BaseModel):
    advice_type: str
    document_text: str
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False


def _hash_sr(text: str) -> str:
    # deterministic hash of the submitted text (we do NOT store full SR in DB)
    t = (text or "").strip().encode("utf-8")
    return hashlib.sha256(t).hexdigest()


def _save_run(context: Dict[str, Any], sr_text: str, result: Dict[str, Any]) -> None:
    run_id = str(uuid.uuid4())
    sr_hash = _hash_sr(sr_text)
    sr_len = len((sr_text or "").strip())

    summary = result.get("summary", {})
    ruleset_id = result.get("ruleset_id", "unknown-ruleset")
    ruleset_version = result.get("ruleset_version", result.get("ruleset_version", "0.0"))

    db = SessionLocal()
    try:
        row = Run(
            id=run_id,
            created_at=result.get("checked_at") and None or None,  # ignored; we set below
            ruleset_id=str(ruleset_id),
            ruleset_version=str(ruleset_version),
            advice_type=str(context.get("advice_type", "")),
            investment_element="true" if bool(context.get("investment_element")) else "false",
            ongoing_service="true" if bool(context.get("ongoing_service")) else "false",
            sr_hash=sr_hash,
            sr_len=sr_len,
            summary_json=Run.dumps(summary if isinstance(summary, dict) else {}),
            result_json=Run.dumps(result if isinstance(result, dict) else {}),
        )

        # set created_at safely (checked_at is string in your executor)
        from datetime import datetime, timezone
        row.created_at = datetime.now(timezone.utc).replace(tzinfo=None)

        db.add(row)
        db.commit()
    finally:
        db.close()


# -------------------------
# CORE API
# -------------------------

@app.post("/check")
async def check(payload: CheckRequest):
    context: Dict[str, Any] = {
        "advice_type": payload.advice_type,
        "investment_element": bool(payload.investment_element),
        "ongoing_service": bool(payload.ongoing_service),
    }

    result = run_rules_engine(
        document_text=payload.document_text,
        context=context,
        rules_path="rules/cobs-suitability-v1.yaml",
    )

    # persist run
    try:
        _save_run(context=context, sr_text=payload.document_text, result=result)
    except Exception:
        # don’t fail the check endpoint if storage fails
        pass

    return JSONResponse(result)


# -------------------------
# ADMIN UI
# -------------------------

@app.get("/admin/test", response_class=HTMLResponse)
async def admin_test_get(request: Request):
    return templates.TemplateResponse(
        "admin_test.html",
        {
            "request": request,
            "result": None,
            "advice_type": "advised",
            "investment_element": "true",
            "ongoing_service": "false",
            "sr_text": "",
        },
    )


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_post(
    request: Request,
    advice_type: str = Form(...),
    investment_element: str = Form("true"),
    ongoing_service: str = Form("false"),
    sr_text: str = Form(""),
):
    inv = (investment_element or "").lower() == "true"
    ong = (ongoing_service or "").lower() == "true"

    ctx: Dict[str, Any] = {
        "advice_type": advice_type,
        "investment_element": inv,
        "ongoing_service": ong,
    }

    result = run_rules_engine(
        document_text=sr_text or "",
        context=ctx,
        rules_path="rules/cobs-suitability-v1.yaml",
    )

    # persist run
    try:
        _save_run(context=ctx, sr_text=sr_text or "", result=result)
    except Exception:
        pass

    return templates.TemplateResponse(
        "admin_test.html",
        {
            "request": request,
            "result": result,
            "advice_type": advice_type,
            "investment_element": "true" if inv else "false",
            "ongoing_service": "true" if ong else "false",
            "sr_text": sr_text or "",
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}

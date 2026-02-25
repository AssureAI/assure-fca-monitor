from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.templating import Jinja2Templates

from pydantic import BaseModel
from typing import Dict, Optional, Any
from datetime import datetime, timezone
import os
import json
import sqlite3
import uuid

from executor import run_rules_engine

# -----------------------------
# APP
# -----------------------------

app = FastAPI(title="Assure Deterministic Compliance Engine")
templates = Jinja2Templates(directory="templates")

RULES_PATH = os.environ.get("RULES_PATH", "rules/cobs-suitability-v1.yaml")
DB_PATH = os.environ.get("ASSURE_DB_PATH", "assure.db")

# -----------------------------
# DB
# -----------------------------

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
              id TEXT PRIMARY KEY,
              created_at TEXT NOT NULL,
              context_json TEXT NOT NULL,
              summary_json TEXT NOT NULL,
              sections_json TEXT NOT NULL,
              ruleset_id TEXT,
              ruleset_version TEXT,
              checked_at TEXT
            )
            """
        )
        conn.commit()

@app.on_event("startup")
def _startup():
    init_db()

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def save_run(result: Dict[str, Any], context: Dict[str, Any]) -> str:
    run_id = str(uuid.uuid4())
    with db() as conn:
        conn.execute(
            """
            INSERT INTO runs
              (id, created_at, context_json, summary_json, sections_json, ruleset_id, ruleset_version, checked_at)
            VALUES
              (?,  ?,          ?,           ?,            ?,            ?,         ?,              ?)
            """,
            (
                run_id,
                utc_now_iso(),
                json.dumps(context),
                json.dumps(result.get("summary", {})),
                json.dumps(result.get("sections", {})),
                result.get("ruleset_id"),
                result.get("ruleset_version"),
                result.get("checked_at"),
            ),
        )
        conn.commit()
    return run_id

def list_runs(limit: int = 50):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, created_at, ruleset_id, ruleset_version, checked_at, summary_json FROM runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "ruleset_id": r["ruleset_id"],
                "ruleset_version": r["ruleset_version"],
                "checked_at": r["checked_at"],
                "summary": json.loads(r["summary_json"] or "{}"),
            }
        )
    return out

def get_run(run_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "ruleset_id": row["ruleset_id"],
        "ruleset_version": row["ruleset_version"],
        "checked_at": row["checked_at"],
        "context": json.loads(row["context_json"] or "{}"),
        "summary": json.loads(row["summary_json"] or "{}"),
        "sections": json.loads(row["sections_json"] or "{}"),
    }

# -----------------------------
# API MODEL
# -----------------------------

class CheckRequest(BaseModel):
    advice_type: str
    document_text: str
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False

# -----------------------------
# CORE API
# -----------------------------

@app.post("/check")
async def check(payload: CheckRequest):
    context: Dict[str, object] = {
        "advice_type": payload.advice_type,
        "investment_element": bool(payload.investment_element),
        "ongoing_service": bool(payload.ongoing_service),
    }

    result = run_rules_engine(
        document_text=payload.document_text,
        context=context,
        rules_path=RULES_PATH,
    )

    return JSONResponse(result)

# -----------------------------
# ADMIN UI
# -----------------------------

@app.get("/admin/test", response_class=HTMLResponse)
def admin_test_get(request: Request):
    return templates.TemplateResponse(
        "admin_test.html",
        {
            "request": request,
            "result": None,
            "advice_type": "advised",
            "investment_element": "true",
            "ongoing_service": "false",
            "sr_text": "",
            "result_json": None,
            "run_id": None,
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
    ctx = {
        "advice_type": advice_type,
        "investment_element": (investment_element or "").lower() == "true",
        "ongoing_service": (ongoing_service or "").lower() == "true",
    }

    result = run_rules_engine(
        document_text=sr_text or "",
        context=ctx,
        rules_path=RULES_PATH,
    )

    # persist run
    run_id = save_run(result, ctx)

    return templates.TemplateResponse(
        "admin_test.html",
        {
            "request": request,
            "result": result,
            "result_json": json.dumps(result, ensure_ascii=False, indent=2),
            "run_id": run_id,
            "advice_type": advice_type,
            "investment_element": investment_element,
            "ongoing_service": ongoing_service,
            "sr_text": sr_text,
        },
    )

# -----------------------------
# RUN HISTORY (THIS FIXES YOUR 404)
# -----------------------------

@app.get("/admin/runs", response_class=HTMLResponse)
def admin_runs(request: Request):
    runs = list_runs(limit=100)
    return templates.TemplateResponse(
        "runs.html",
        {"request": request, "runs": runs},
    )

@app.get("/admin/runs/{run_id}", response_class=HTMLResponse)
def admin_run_detail(request: Request, run_id: str):
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return templates.TemplateResponse(
        "run_detail.html",
        {"request": request, "run": run},
    )

# -----------------------------
# HEALTH
# -----------------------------

@app.get("/health")
def health():
    return {"status": "ok", "rules_path": RULES_PATH}

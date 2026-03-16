# main.py
from __future__ import annotations
from collections import Counter

import os
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from collections import Counter
from collections import Counter, defaultdict

from fastapi import FastAPI, Request, Form, HTTPException, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from pypdf import PdfReader
from docx import Document

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from io import BytesIO

from pydantic import BaseModel

from executor import run_rules_engine
from llm_guidance import (
    build_rule_guidance_prompt,
    sanitize_for_llm,
)
from llm_client import get_rule_guidance, MODEL as LLM_MODEL
from database import (
    SessionLocal,
    init_db,
    Firm,
    User,
    Run,
    LlmGuidanceLog,
    hash_password,
    verify_password,
    create_session,
    delete_session,
    get_user_by_session_token,
    DB_URL,
)

# -----------------------------
# APP
# -----------------------------

app = FastAPI(title="Rulegrid Compliance Engine")
templates = Jinja2Templates(directory="templates")

# Static assets
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Rules path
RULES_PATH = os.environ.get("RULES_PATH", "rules/cobs-mvp-v2.yaml")

# Cookies
SESSION_COOKIE = os.environ.get("RULEGRID_SESSION_COOKIE", os.environ.get("ASSURE_SESSION_COOKIE", "rulegrid_session"))
COOKIE_SECURE = os.environ.get("RULEGRID_COOKIE_SECURE", os.environ.get("ASSURE_COOKIE_SECURE", "true")).lower() == "true"

# Bootstrap admin
BOOTSTRAP_EMAIL = os.environ.get("RULEGRID_BOOTSTRAP_EMAIL", os.environ.get("ASSURE_BOOTSTRAP_EMAIL", "")).strip().lower()
BOOTSTRAP_PASSWORD = os.environ.get("RULEGRID_BOOTSTRAP_PASSWORD", os.environ.get("ASSURE_BOOTSTRAP_PASSWORD", ""))
BOOTSTRAP_FIRM = os.environ.get("RULEGRID_BOOTSTRAP_FIRM", os.environ.get("ASSURE_BOOTSTRAP_FIRM", "Demo Firm"))

# App secret (required)
APP_SECRET = os.environ.get("RULEGRID_APP_SECRET", os.environ.get("ASSURE_APP_SECRET", "")).strip()

# -----------------------------
# DB DEPENDENCY
# -----------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -----------------------------
# HELPERS
# -----------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)

def utc_now_iso() -> str:
    return utc_now().isoformat()

def get_session_token_from_request(request: Request) -> str:
    return request.cookies.get(SESSION_COOKIE, "") or ""

def require_user_html(request: Request, db=Depends(get_db)) -> User:
    token = get_session_token_from_request(request)
    user = get_user_by_session_token(db, token)
    if not user:
        raise HTTPException(status_code=401, detail="LOGIN_REQUIRED")
    return user

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and exc.detail == "LOGIN_REQUIRED":
        return RedirectResponse(url="/login", status_code=303)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

def compute_completeness(summary: Dict[str, Any]) -> int:
    """Completeness % = OK / (OK + POTENTIAL_ISSUE). NOT_ASSESSED excluded."""
    ok = int(summary.get("ok", 0) or 0)
    pi = int(summary.get("potential_issue", 0) or 0)
    denom = ok + pi
    if denom <= 0:
        return 0
    return int(round((ok / denom) * 100))

def review_band(score: int) -> str:
    if score >= 85:
        return "Green"
    if score >= 70:
        return "Amber"
    return "Red"
    
def summarise_issue(rule: Dict[str, Any]) -> str:
    why = (rule.get("why") or "").strip()
    if why == "No supporting wording found in the report.":
        return "No supporting wording found in the report."
    if why == "Conditions not met.":
        return "The report doesn’t clearly evidence this requirement."
    if why == "No decision_logic provided (cannot auto-pass).":
        return "This rule cannot be assessed due to an incomplete ruleset configuration."
    if not why:
        return "The report doesn’t clearly evidence this requirement."
    return why

def extract_action_items(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    sections = result.get("sections") or {}
    if not isinstance(sections, dict):
        return out

    for section_name, rules in sections.items():
        if not isinstance(rules, list):
            continue
        for r in rules:
            if not isinstance(r, dict):
                continue
            if r.get("status") != "POTENTIAL_ISSUE":
                continue

            fixes = r.get("fixes") or []
            if not isinstance(fixes, list):
                fixes = []

            suggested = r.get("suggested_wording") or []
            if not isinstance(suggested, list):
                suggested = []

            evidence = r.get("evidence") or []
            if not isinstance(evidence, list):
                evidence = []

            out.append(
                {
                    "section": section_name,
                    "rule_id": r.get("rule_id", ""),
                    "title": r.get("title", "") or (r.get("rule_id", "") or "Issue"),
                    "citation": r.get("citation", ""),
                    "source_url": r.get("source_url", ""),
                    "issue_summary": summarise_issue(r),
                    "fixes": fixes,
                    "suggestions": suggested if suggested else ["Update the report to clearly evidence this requirement, then rerun the check."],
                    "evidence": evidence[:6],
                }
            )

    # deterministic “top” ordering: by section then rule id
    out = sorted(out, key=lambda x: ((x.get("section") or ""), (x.get("rule_id") or "")))
    return out

def _safe_split_first(s: str, sep: str = "@") -> str:
    if sep in s:
        return s.split(sep, 1)[-1]
    return s

async def extract_uploaded_text(upload: Optional[UploadFile]) -> str:
    if not upload or not upload.filename:
        return ""

    filename = (upload.filename or "").lower()

    try:
        raw = await upload.read()
        print("upload filename:", filename)
        print("upload bytes:", len(raw) if raw else 0)

        if not raw:
            return ""

        if filename.endswith(".txt"):
            text = raw.decode("utf-8", errors="ignore").strip()
            print("extracted txt length:", len(text))
            return text

        if filename.endswith(".pdf"):
            reader = PdfReader(BytesIO(raw))
            pages = []
            for i, page in enumerate(reader.pages):
                page_text = page.extract_text() or ""
                pages.append(page_text)
                print(f"pdf page {i+1} text length:", len(page_text))
            text = "\n".join(pages).strip()
            print("extracted pdf length:", len(text))
            return text

        if filename.endswith(".docx"):
            doc = Document(BytesIO(raw))
            text = "\n".join([p.text for p in doc.paragraphs]).strip()
            print("extracted docx length:", len(text))
            return text

        print("unsupported upload type:", filename)
        return ""

    except Exception as e:
        print("extract_uploaded_text failed:", type(e).__name__, str(e))
        return ""
    
def persist_run(db, user: User, result: Dict[str, Any], context: Dict[str, Any], sr_text: str) -> str:
    run_id = str(uuid.uuid4())
    sr_hash = hashlib.sha256((sr_text or "").encode("utf-8")).hexdigest()

    summary = result.get("summary", {}) or {}
    ok_count = int(summary.get("ok", 0) or 0)
    pi_count = int(summary.get("potential_issue", 0) or 0)
    na_count = int(summary.get("not_assessed", 0) or 0)
    completeness_pct = compute_completeness(summary)

    r = Run(
        id=run_id,
        firm_id=user.firm_id,
        user_id=user.id,
        ruleset_id=result.get("ruleset_id") or "",
        ruleset_version=result.get("ruleset_version") or "",
        checked_at=result.get("checked_at") or utc_now_iso(),
        advice_type=str(context.get("advice_type") or ""),
        investment_element="true" if bool(context.get("investment_element")) else "false",
        ongoing_service="true" if bool(context.get("ongoing_service")) else "false",
        sr_hash=sr_hash,
        sr_len=len(sr_text or ""),
        ok_count=ok_count,
        pi_count=pi_count,
        na_count=na_count,
        completeness_pct=completeness_pct,
        summary_json=json.dumps(summary, ensure_ascii=False),
        sections_json=json.dumps(result.get("sections", {}), ensure_ascii=False),
    )
    db.add(r)
    db.commit()
    return run_id

def generate_exec_summary(
    *,
    result: Dict[str, Any],
    summary: Dict[str, Any],
    completeness_pct: int,
    action_items: List[Dict[str, Any]],
) -> str:
    ok = int(summary.get("ok", 0) or 0)
    pi = int(summary.get("potential_issue", 0) or 0)
    assessed = ok + pi

    if completeness_pct >= 85:
        status = "Green"
        opening = "Overall status: Green. The file is broadly in good order."
    elif completeness_pct >= 70:
        status = "Amber"
        opening = "Overall status: Amber. The file is workable, but there are a few points to tighten before issue."
    else:
        status = "Red"
        opening = "Overall status: Red. The file is not ready for issue in its current form."

    if assessed <= 0:
        assessment = "No assessed controls were evidenced in this run."
    else:
        assessment = f"{ok} of {assessed} assessed checks were met (completeness {completeness_pct}%)."

    top = action_items[:3]
    if top:
        top_lines = "\n".join([f"- {t.get('title') or t.get('rule_id') or 'Issue'}" for t in top])
        priorities = f"Priority review areas:\n{top_lines}"
    else:
        priorities = "Priority review areas:\n- No material issues were flagged by the ruleset."

    consumer_duty_flags = {((a.get("rule_id") or "").strip()) for a in action_items if (a.get("rule_id") or "").startswith("CD_")}
    cd_lines: List[str] = []
    if "CD_UNDERSTANDING_JARGON_BRIDGE" in consumer_duty_flags:
        cd_lines.append("- Consumer Understanding: jargon or technical phrasing may need plainer explanation.")
    if "CD_VULNERABILITY_SUPPORT_MEASURE" in consumer_duty_flags:
        cd_lines.append("- Vulnerability: the file may need a clearer record of any support adjustments made.")
    if "CD_SLUDGE_FRICTION" in consumer_duty_flags:
        cd_lines.append("- Support: wording may need a fairness check for friction or unnecessary barriers.")

    cd_block = ""
    if cd_lines:
        cd_block = "\n\nConsumer Duty watchouts:\n" + "\n".join(cd_lines)

    return f"{opening}\n\nAssessment:\n{assessment}\n\n{priorities}{cd_block}"

# -----------------------------
# BOOTSTRAP
# -----------------------------

def ensure_bootstrap_admin(db) -> None:
    if not APP_SECRET:
        raise RuntimeError("RULEGRID_APP_SECRET must be set in environment.")

    existing = db.query(User).first()
    if existing:
        return

    if not BOOTSTRAP_EMAIL or not BOOTSTRAP_PASSWORD:
        raise RuntimeError(
            "No users exist yet. Set RULEGRID_BOOTSTRAP_EMAIL and RULEGRID_BOOTSTRAP_PASSWORD to create the first admin."
        )

    firm = Firm(name=BOOTSTRAP_FIRM)
    db.add(firm)
    db.commit()
    db.refresh(firm)

    admin = User(
        firm_id=firm.id,
        email=BOOTSTRAP_EMAIL,
        password_hash=hash_password(BOOTSTRAP_PASSWORD),
        role="admin",
        is_active=1,
    )
    db.add(admin)
    db.commit()

@app.on_event("startup")
def _startup():
    init_db()
    db = SessionLocal()
    try:
        ensure_bootstrap_admin(db)
    finally:
        db.close()

# -----------------------------
# API MODEL
# -----------------------------

class CheckRequest(BaseModel):
    advice_type: str
    document_text: str
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False


class RuleGuidanceRequest(BaseModel):
    rule_id: str
    title: str
    citation: str
    decision_logic: str
    evidence: List[str] = []
    fixes: List[str] = []
    section: str

    model_config = {"extra": "forbid"}


class RuleGuidanceResponse(BaseModel):
    guidance: str


# -----------------------------
# CORE API (AUTHED)
# -----------------------------

@app.post("/check")
async def check(payload: CheckRequest, request: Request, db=Depends(get_db)):
    user = get_user_by_session_token(db, get_session_token_from_request(request))
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    context: Dict[str, Any] = {
        "advice_type": payload.advice_type,
        "investment_element": bool(payload.investment_element),
        "ongoing_service": bool(payload.ongoing_service),
    }

    try:
        result = run_rules_engine(
            document_text=payload.document_text,
            context=context,
            rules_path=RULES_PATH,
        )
    except Exception as e:
        # Don’t 500 with no clue.
        return JSONResponse(
            {"detail": "RULES_ENGINE_ERROR", "error": str(e), "rules_path": RULES_PATH},
            status_code=500,
        )

    run_id = persist_run(db, user, result, context, payload.document_text or "")
    result_out = dict(result)
    result_out["run_id"] = run_id
    result_out["completeness_pct"] = compute_completeness(result.get("summary", {}) or {})
    return JSONResponse(result_out)


# -----------------------------
# LLM RULE GUIDANCE (STUB, NO REAL LLM)
# -----------------------------

RULE_GUIDANCE_DISCLAIMER = (
    "This guidance is generated automatically to help interpret rule results. "
    "It does not constitute compliance advice or regulatory guidance."
)


def _is_guidance_error(text: str) -> bool:
    if not text or not text.strip():
        return True
    t = text.strip()
    if t == "LLM not configured.":
        return True
    if t.startswith("OpenAI error ") or t.startswith("LLM request failed:"):
        return True
    if t.startswith("Unable to generate") or t.startswith("OpenAI success but no"):
        return True
    return False


@app.post("/llm/rule_guidance")
async def llm_rule_guidance(payload: RuleGuidanceRequest, request: Request, db=Depends(get_db)):
    user = get_user_by_session_token(db, get_session_token_from_request(request))
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    safe = {
        "rule_id": sanitize_for_llm(payload.rule_id or ""),
        "title": sanitize_for_llm(payload.title or ""),
        "citation": sanitize_for_llm(payload.citation or ""),
        "decision_logic": sanitize_for_llm(payload.decision_logic or ""),
        "evidence": [sanitize_for_llm(x) for x in (payload.evidence or [])],
        "fixes": [sanitize_for_llm(x) for x in (payload.fixes or [])],
        "section": sanitize_for_llm(payload.section or ""),
    }
    prompt = build_rule_guidance_prompt(**safe)
    request_payload_sanitized = json.dumps(safe, ensure_ascii=False)

    log_row = LlmGuidanceLog(
        user_id=user.id,
        rule_id=safe["rule_id"],
        title=safe["title"],
        citation=safe["citation"],
        section=safe["section"],
        request_payload_sanitized=request_payload_sanitized,
        prompt_text=prompt,
        llm_response_text=None,
        status="pending",
        error_text=None,
        model_name=LLM_MODEL,
    )
    db.add(log_row)
    db.flush()

    try:
        text = get_rule_guidance(prompt)
        if not text:
            text = "Unable to generate guidance."

        if _is_guidance_error(text):
            log_row.status = "error"
            log_row.error_text = text[:5000]
        else:
            log_row.status = "success"
            log_row.llm_response_text = text[:50000]
    except Exception as e:
        log_row.status = "error"
        log_row.error_text = str(e)[:5000]
        text = "Unable to generate guidance."
    db.commit()

    guidance = text.strip() + "\n\n" + RULE_GUIDANCE_DISCLAIMER
    return JSONResponse(RuleGuidanceResponse(guidance=guidance).model_dump())


# -----------------------------
# LOGIN / LOGOUT (HTML)
# -----------------------------

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None,
            "next_path": "/demo",
            "login_title": "Paraplanner login",
            "login_subtitle": "For SR review and pre-issue checking.",
        },
    )

@app.get("/oversight/login", response_class=HTMLResponse)
def oversight_login_get(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None,
            "next_path": "/admin/mi",
            "login_title": "Oversight / Risk login",
            "login_subtitle": "For QA, oversight and management information.",
        },
    )

@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next_path: str = Form("/demo"),
    db=Depends(get_db),
):
    email_n = (email or "").strip().lower()
    user = db.query(User).filter(User.email == email_n).first()
    if not user or not user.is_active or not verify_password(password or "", user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=401)
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Invalid credentials",
                "next_path": next_path or "/demo",
                "login_title": "Login",
                "login_subtitle": "",
            },
            status_code=401,
        )
        
    token = create_session(db, user.id)
    user.last_login_at = utc_now()
    db.commit()

    safe_next = next_path if next_path in ["/demo", "/admin/mi"] else "/demo"
    resp = RedirectResponse(url=safe_next, status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24 * 14,
        path="/",
    )
    return resp

@app.get("/logout")
def logout_get(request: Request, db=Depends(get_db)):
    token = get_session_token_from_request(request)
    if token:
        delete_session(db, token)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.post("/logout")
def logout_post(request: Request, db=Depends(get_db)):
    return logout_get(request, db)

# -----------------------------
# DEMO UI (AUTHED)
# -----------------------------

@app.get("/demo", response_class=HTMLResponse)
def demo_get(request: Request, user: User = Depends(require_user_html)):
    return templates.TemplateResponse(
        "demo.html",
        {
            "request": request,
            "user_email": user.email,
            "defaults": {"advice_type": "advised", "investment_element": "true", "ongoing_service": "false"},
        },
    )

@app.post("/demo/run", response_class=HTMLResponse)
async def demo_run_post(
    request: Request,
    advice_type: str = Form(...),
    investment_element: str = Form("true"),
    ongoing_service: str = Form("false"),
    sr_text: str = Form(""),
    sr_file: Optional[UploadFile] = File(None),
    user: User = Depends(require_user_html),
    db=Depends(get_db),
):
    ctx = {
        "advice_type": advice_type,
        "investment_element": (investment_element or "").lower() == "true",
        "ongoing_service": (ongoing_service or "").lower() == "true",
    }

    print("sr_file present:", bool(sr_file))
    print("sr_file name:", getattr(sr_file, "filename", None))
    print("sr_text length:", len((sr_text or "").strip()))

    uploaded_text = await extract_uploaded_text(sr_file)
    print("uploaded_text length:", len((uploaded_text or "").strip()))

    final_sr_text = (sr_text or "").strip()

    if uploaded_text and final_sr_text:
        final_sr_text = uploaded_text + "\n\n" + final_sr_text
    elif uploaded_text:
        final_sr_text = uploaded_text

    if not (final_sr_text or "").strip():
        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "run_id": "",
                "result": {
                    "sections": {
                        "INPUT ERROR": [
                            {
                                "rule_id": "NO_INPUT",
                                "title": "No report text received",
                                "status": "POTENTIAL_ISSUE",
                                "citation": "",
                                "source_url": "",
                                "why": "The uploaded file was not converted into usable text, and no pasted text was provided.",
                                "fixes": [
                                    "Paste the report text directly into the text box.",
                                    "If uploading, use a supported file type that text extraction can actually read.",
                                    "Check the upload parser for the selected file type."
                                ],
                                "suggested_wording": [],
                                "counts": {},
                                "missing": [],
                                "details": [],
                                "evidence": [],
                                "evidence_by_key": {},
                            }
                        ]
                    },
                    "summary": {"ok": 0, "potential_issue": 1, "not_assessed": 0},
                },
                "summary": {"ok": 0, "potential_issue": 1, "not_assessed": 0},
                "completeness_pct": 0,
                "action_items": [
                    {
                        "section": "INPUT ERROR",
                        "rule_id": "NO_INPUT",
                        "title": "No report text received",
                        "citation": "",
                        "source_url": "",
                        "issue_summary": "The server did not receive usable report text from the upload.",
                        "fixes": [
                            "Paste the report text directly into the text box.",
                            "If uploading, use a supported file type that text extraction can actually read.",
                            "Check the upload parser for the selected file type."
                        ],
                        "evidence": [],
                        "suggested_wording": [],
                    }
                ],
                "exec_summary": "No report text was received, so the check could not run.",
                "engine_error": "",
                "rules_path_used": RULES_PATH,
            },
            status_code=400,
        )

    try:
        result = run_rules_engine(
            document_text=final_sr_text or "",
            context=ctx,
            rules_path=RULES_PATH,
        )
    except Exception as e:
        # This is almost certainly your “Internal Server Error”.
        # We render the error on-screen so you can fix fast.
        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "run_id": "",
                "result": {"sections": {}, "summary": {"ok": 0, "potential_issue": 0, "not_assessed": 0}},
                "summary": {"ok": 0, "potential_issue": 0, "not_assessed": 0},
                "completeness_pct": 0,
                "action_items": [],
                "exec_summary": "The rules engine failed to run. See error details below.",
                "engine_error": f"{type(e).__name__}: {e}",
                "rules_path_used": RULES_PATH,
            },
            status_code=500,
        )

    run_id = persist_run(db, user, result, ctx, final_sr_text or "")
    return RedirectResponse(url=f"/demo/results/{run_id}", status_code=303)

@app.get("/demo/results/{run_id}", response_class=HTMLResponse)
def demo_results_get(
    request: Request,
    run_id: str,
    user: User = Depends(require_user_html),
    db=Depends(get_db),
):
    rr = db.query(Run).filter(Run.id == run_id, Run.firm_id == user.firm_id).first()
    if not rr:
        raise HTTPException(status_code=404, detail="Run not found")

    result = {
        "ruleset_id": rr.ruleset_id,
        "ruleset_version": rr.ruleset_version,
        "checked_at": rr.checked_at,
        "summary": json.loads(rr.summary_json or "{}"),
        "sections": json.loads(rr.sections_json or "{}"),
    }

    summary = result.get("summary") or {}
    completeness_pct = compute_completeness(summary)
    action_items = extract_action_items(result)

    exec_summary = generate_exec_summary(
        result=result,
        summary=summary,
        completeness_pct=completeness_pct,
        action_items=action_items,
    )

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "run_id": run_id,
            "result": result,
            "summary": summary,
            "completeness_pct": completeness_pct,
            "action_items": action_items,
            "exec_summary": exec_summary,
            "engine_error": None,
            "rules_path_used": RULES_PATH,
        },
    )

@app.get("/demo/export/{run_id}")
async def export_compliance_review(
    run_id: str,
    user: User = Depends(require_user_html),
    db=Depends(get_db),
):

    rr = db.query(Run).filter(Run.id == run_id, Run.firm_id == user.firm_id).first()
    if not rr:
        raise HTTPException(status_code=404, detail="Run not found")
    
    result = {
        "ruleset_id": rr.ruleset_id,
        "ruleset_version": rr.ruleset_version,
        "checked_at": rr.checked_at,
        "summary": json.loads(rr.summary_json or "{}"),
        "sections": json.loads(rr.sections_json or "{}"),
    }

    buffer = BytesIO()

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("RuleGrid Compliance Review", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"Run ID: {run_id}", styles["Normal"]))
    story.append(Paragraph(f"Ruleset Version: {result.get('ruleset_version')}", styles["Normal"]))
    story.append(Paragraph(f"Checked At: {str(result.get('checked_at') or '')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    summary = result.get("summary", {})

    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(Paragraph(f"OK: {summary.get('ok')}", styles["Normal"]))
    story.append(Paragraph(f"Potential Issues: {summary.get('potential_issue')}", styles["Normal"]))
    story.append(Paragraph(f"Not Assessed: {summary.get('not_assessed')}", styles["Normal"]))
    story.append(Spacer(1, 20))

    for section, rules in result.get("sections", {}).items():

        story.append(Paragraph(section, styles["Heading2"]))
        story.append(Spacer(1, 8))

        for r in rules:

            story.append(Paragraph(f"{r['rule_id']} — {r['title']}", styles["Heading3"]))
            story.append(Paragraph(f"Status: {r['status']}", styles["Normal"]))
            story.append(Paragraph(f"Citation: {r.get('citation','')}", styles["Normal"]))
            story.append(Paragraph(f"Why: {r.get('why','')}", styles["Normal"]))

            if r.get("suggested_wording"):
                story.append(Paragraph("Suggested wording:", styles["Italic"]))
                for s in r["suggested_wording"]:
                    story.append(Paragraph(s, styles["Normal"]))

            story.append(Spacer(1, 10))

    doc = SimpleDocTemplate(buffer)
    doc.build(story)

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=rulegrid-review-{run_id}.pdf"
        },
    )
    
@app.get("/demo/results/{run_id}/pdf")
def download_pdf(run_id: str, user: User = Depends(require_user_html), db=Depends(get_db)):
    rr = db.query(Run).filter(Run.id == run_id, Run.firm_id == user.firm_id).first()
    if not rr:
        raise HTTPException(status_code=404, detail="Run not found")

    result = {
        "summary": json.loads(rr.summary_json or "{}"),
        "sections": json.loads(rr.sections_json or "{}"),
    }
    action_items = extract_action_items({"sections": result.get("sections", {})})

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    elements = []
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    heading = styles["Heading1"]

    elements.append(Paragraph("Rulegrid Compliance Report", heading))
    elements.append(Spacer(1, 0.3 * inch))

    summary = result.get("summary", {})
    elements.append(Paragraph(f"OK: {summary.get('ok',0)}", normal))
    elements.append(Paragraph(f"Issues: {summary.get('potential_issue',0)}", normal))
    elements.append(Spacer(1, 0.3 * inch))

    for item in action_items:
        elements.append(Paragraph(item["title"], styles["Heading2"]))
        elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph("What to fix:", styles["Heading3"]))
        fixes = [ListItem(Paragraph(f, normal)) for f in (item.get("fixes") or [])]
        if fixes:
            elements.append(ListFlowable(fixes, bulletType="bullet"))

        suggestions = item.get("suggestions") or []
        if suggestions:
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph("Example wording per FCA guidance:", styles["Heading3"]))
            sug = [ListItem(Paragraph(s, normal)) for s in suggestions]
            elements.append(ListFlowable(sug, bulletType="bullet"))

        elements.append(Spacer(1, 0.35 * inch))

    doc.build(elements)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=rulegrid-run-{run_id}.pdf"},
    )

# -----------------------------
# ADMIN RUN HISTORY (AUTHED)
# -----------------------------

@app.get("/admin/runs", response_class=HTMLResponse)
def admin_runs(request: Request, user: User = Depends(require_user_html), db=Depends(get_db)):
    rows = (
        db.query(Run)
        .filter(Run.firm_id == user.firm_id)
        .order_by(Run.created_at.desc())
        .limit(200)
        .all()
    )

    runs = []
    for rr in rows:
        runs.append(
            {
                "id": rr.id,
                "created_at": rr.created_at.isoformat() if rr.created_at else "",
                "ruleset_id": rr.ruleset_id,
                "ruleset_version": rr.ruleset_version,
                "checked_at": rr.checked_at,
                "summary": json.loads(rr.summary_json or "{}"),
            }
        )

    return templates.TemplateResponse("runs.html", {"request": request, "runs": runs, "user_email": user.email})

@app.get("/admin/mi", response_class=HTMLResponse)
def admin_mi(
    request: Request,
    rule_id: Optional[str] = None,
    user: User = Depends(require_user_html),
    db=Depends(get_db),
):
    rows = (
        db.query(Run)
        .filter(Run.firm_id == user.firm_id)
        .order_by(Run.created_at.desc())
        .limit(1000)
        .all()
    )

    total_runs = len(rows)
    score_total = 0
    above_75 = 0

    band_counts = {"Green": 0, "Amber": 0, "Red": 0}
    rule_counter: Counter = Counter()
    section_counter: Counter = Counter()
    theme_counter: Counter = Counter()
    trend_counter: Counter = Counter()
    cd_counter: Counter = Counter()

    user_issue_counter: Counter = Counter()
    user_run_counter: Counter = Counter()
    user_score_totals = defaultdict(int)

    escalation_runs = []
    selected_rule_runs = []
    recent_runs = []

    for rr in rows:
        summary = json.loads(rr.summary_json or "{}")
        sections = json.loads(rr.sections_json or "{}")
        score = compute_completeness(summary)
        band = review_band(score)

        score_total += score
        if score >= 75:
            above_75 += 1
        band_counts[band] += 1

        created_day = rr.created_at.date().isoformat() if rr.created_at else "Unknown"
        trend_counter[created_day] += 1

        pi_count = int(summary.get("potential_issue", 0) or 0)
        user_key = str(rr.user_id or "unknown")
        user_issue_counter[user_key] += pi_count
        user_run_counter[user_key] += 1
        user_score_totals[user_key] += score

        recent_runs.append(
            {
                "id": rr.id,
                "created_at": rr.created_at.isoformat() if rr.created_at else "",
                "ruleset_id": rr.ruleset_id or "",
                "ruleset_version": rr.ruleset_version or "",
                "completeness_pct": score,
                "score": score,
                "band": band,
                "pi_count": pi_count,
            }
        )

        if score < 60 or pi_count >= 5:
            escalation_runs.append(
                {
                    "id": rr.id,
                    "created_at": rr.created_at.isoformat() if rr.created_at else "",
                    "score": score,
                    "pi_count": pi_count,
                    "band": band,
                }
            )

        if isinstance(sections, dict):
            for section_name, rules in sections.items():
                if not isinstance(rules, list):
                    continue

                section_has_issue = False

                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    if rule.get("status") != "POTENTIAL_ISSUE":
                        continue

                    section_has_issue = True
                    rid = (rule.get("rule_id") or "").strip()
                    title = (rule.get("title") or rid).strip()

                    if rid:
                        rule_counter[rid] += 1
                        if rule_id and rid == rule_id:
                            selected_rule_runs.append(
                                {
                                    "run_id": rr.id,
                                    "created_at": rr.created_at.isoformat() if rr.created_at else "",
                                    "section": section_name,
                                    "score": score,
                                    "title": title,
                                }
                            )

                    title_l = title.lower()
                    section_l = section_name.lower()

                    if "suitability" in title_l or "suitability" in section_l:
                        theme_counter["Suitability rationale"] += 1
                    elif "risk" in title_l or "risk" in section_l:
                        theme_counter["Risk explanation"] += 1
                    elif "cost" in title_l or "charge" in title_l:
                        theme_counter["Charges and disclosures"] += 1
                    elif rid.startswith("CD_UNDERSTANDING"):
                        theme_counter["Consumer understanding"] += 1
                        cd_counter["Consumer understanding"] += 1
                    elif rid.startswith("CD_VULNERABILITY"):
                        theme_counter["Vulnerability"] += 1
                        cd_counter["Vulnerability"] += 1
                    elif rid.startswith("CD_SLUDGE") or rid.startswith("CD_SUPPORT"):
                        theme_counter["Support / friction"] += 1
                        cd_counter["Support / friction"] += 1

                if section_has_issue:
                    section_counter[section_name] += 1

    average_score = round(score_total / total_runs, 1) if total_runs else 0.0
    above_75_pct = round((above_75 / total_runs) * 100, 1) if total_runs else 0.0

    trend = [{"day": day, "count": trend_counter[day]} for day in sorted(trend_counter.keys())]
    top_rules = [{"rule_id": rid, "count": count} for rid, count in rule_counter.most_common(10)]
    top_sections = [{"section": sec, "count": count} for sec, count in section_counter.most_common(10)]
    top_themes = [{"theme": theme, "count": count} for theme, count in theme_counter.most_common(8)]
    cd_watch = [{"name": name, "count": count} for name, count in cd_counter.most_common(6)]

    user_ids = [uid for uid in user_run_counter.keys() if uid != "unknown"]
    user_lookup = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        user_lookup = {str(u.id): (u.email or str(u.id)) for u in users}

    risk_by_user = []
    for uid, runs_count in user_run_counter.items():
        avg_score = round(user_score_totals[uid] / runs_count, 1) if runs_count else 0.0
        issue_count = int(user_issue_counter[uid] or 0)

        if avg_score >= 85:
            user_band = "Green"
        elif avg_score >= 70:
            user_band = "Amber"
        else:
            user_band = "Red"

        risk_by_user.append(
            {
                "user_label": user_lookup.get(uid, uid),
                "runs": runs_count,
                "issues": issue_count,
                "avg_score": avg_score,
                "band": user_band,
            }
        )

    risk_by_user.sort(key=lambda x: (-x["issues"], x["avg_score"]))

    return templates.TemplateResponse(
        "mi.html",
        {
            "request": request,
            "user_email": user.email,
            "total_runs": total_runs,
            "average_score": average_score,
            "above_75": above_75,
            "above_75_pct": above_75_pct,
            "band_counts": band_counts,
            "top_rules": top_rules,
            "top_sections": top_sections,
            "top_themes": top_themes,
            "cd_watch": cd_watch,
            "trend": trend,
            "selected_rule_id": rule_id,
            "selected_rule_runs": selected_rule_runs,
            "recent_runs": recent_runs[:20],
            "escalation_runs": escalation_runs[:20],
            "risk_by_user": risk_by_user[:20],
        },
    )
    
@app.get("/admin/runs/{run_id}", response_class=HTMLResponse)
def admin_run_detail(request: Request, run_id: str, user: User = Depends(require_user_html), db=Depends(get_db)):
    rr = db.query(Run).filter(Run.id == run_id, Run.firm_id == user.firm_id).first()
    if not rr:
        raise HTTPException(status_code=404, detail="Run not found")

    run = {
        "id": rr.id,
        "created_at": rr.created_at.isoformat() if rr.created_at else "",
        "ruleset_id": rr.ruleset_id,
        "ruleset_version": rr.ruleset_version,
        "checked_at": rr.checked_at,
        "summary": json.loads(rr.summary_json or "{}"),
        "sections": json.loads(rr.sections_json or "{}"),
        "advice_type": rr.advice_type,
        "investment_element": rr.investment_element,
        "ongoing_service": rr.ongoing_service,
        "sr_hash": rr.sr_hash,
        "sr_len": rr.sr_len,
    }

    return templates.TemplateResponse("run_detail.html", {"request": request, "run": run, "user_email": user.email})

@app.get("/admin/users", response_class=HTMLResponse)
def manage_users(request: Request, user: User = Depends(require_user_html), db=Depends(get_db)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    users = db.query(User).filter(User.firm_id == user.firm_id).all()
    return templates.TemplateResponse("users.html", {"request": request, "users": users})

@app.post("/admin/users/create", response_class=HTMLResponse)
def create_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form("member"),
    user: User = Depends(require_user_html),
    db=Depends(get_db),
):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    email_clean = (email or "").strip().lower()

    existing = (
        db.query(User)
        .filter(User.email == email_clean, User.firm_id == user.firm_id)
        .first()
    )

    users = db.query(User).filter(User.firm_id == user.firm_id).all()

    if existing:
        return templates.TemplateResponse(
            "users.html",
            {"request": request, "users": users, "error": "User with this email already exists"},
            status_code=400,
        )

    new_user = User(
        firm_id=user.firm_id,
        email=email_clean,
        password_hash=hash_password(password),
        role=role,
        is_active=1,
    )

    db.add(new_user)
    db.commit()

    users = db.query(User).filter(User.firm_id == user.firm_id).all()
    return templates.TemplateResponse(
        "users.html",
        {"request": request, "users": users, "success": "User created successfully"},
    )

# -----------------------------
# HEALTH / ROOT
# -----------------------------

@app.get("/health")
def health():
    safe_db = None
    if DB_URL:
        safe_db = _safe_split_first(DB_URL, "@")
    return {
        "status": "ok",
        "rules_path": RULES_PATH,
        "db": safe_db,
        "db_driver": "sqlite" if (DB_URL or "").startswith("sqlite") else "postgres",
    }

@app.get("/", response_class=PlainTextResponse)
def root():
    return "Rulegrid is running. Visit /login"

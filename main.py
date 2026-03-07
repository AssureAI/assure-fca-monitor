# main.py
from __future__ import annotations

import os
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from io import BytesIO

from pydantic import BaseModel

from executor import run_rules_engine
from database import (
    SessionLocal,
    init_db,
    Firm,
    User,
    Run,
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

    sections = result.get("sections") or {}
    sr_structure = sections.get("SR — Structure") or []
    struct_ok = {r.get("rule_id") for r in sr_structure if r.get("status") == "OK"}

    structured_signals: List[str] = []
    if "SR_STRUCT_CLIENT_DETAILS" in struct_ok:
        structured_signals.append("client/adviser details are clearly captured")
    if "SR_STRUCT_NEXT_STEPS" in struct_ok:
        structured_signals.append("next steps are explicit")

    if structured_signals:
        structure_line = "This suitability report is well structured — " + " and ".join(structured_signals) + "."
    else:
        structure_line = "This suitability report is reasonably structured, but there are a few documentation gaps worth tightening."

    # Consumer Duty signals by rule id prefix
    consumer_duty_flags = {((a.get("rule_id") or "").strip()) for a in action_items if (a.get("rule_id") or "").startswith("CD_")}

    cd_lines: List[str] = []
    if "CD_UNDERSTANDING_JARGON_BRIDGE" in consumer_duty_flags:
        cd_lines.append("Be mindful of Consumer Duty ‘Consumer Understanding’: sophisticated terminology appears without enough plain-English bridging in places.")
    if "CD_VULNERABILITY_SUPPORT_MEASURE" in consumer_duty_flags:
        cd_lines.append("Consumer Duty vulnerability handling: vulnerability indicators appear, but the file doesn’t consistently document the specific support adjustments made.")
    if "CD_SLUDGE_FRICTION" in consumer_duty_flags:
        cd_lines.append("Consumer Duty ‘Support’: potential friction/‘sludge’ wording is present — this needs a quick manual check for fairness and balance.")

    assessed = max(1, ok + pi)
    if completeness_pct >= 85:
        score_line = f"It hits {ok} of {assessed} assessed checks, with a completeness score of {completeness_pct}%."
    elif completeness_pct >= 65:
        score_line = f"It hits {ok} of {assessed} assessed checks (completeness {completeness_pct}%). Solid base, but a few points need tightening."
    else:
        score_line = f"It hits {ok} of {assessed} assessed checks (completeness {completeness_pct}%). This needs a cleanup pass before it’s audit-ready."

    top = action_items[:3]
    if top:
        bullets = "\n".join([f"- {t.get('title') or t.get('rule_id') or 'Issue'}" for t in top])
    else:
        bullets = "- No material issues detected by the ruleset."

    cd_block = ("\n\n" + "\n".join(cd_lines)) if cd_lines else ""

    return (
        f"{structure_line}\n\n"
        f"{score_line}\n\n"
        f"You might want to focus on:\n"
        f"{bullets}\n\n"
        f"For more detail, see the breakdown below."
        f"{cd_block}"
    )

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
# LOGIN / LOGOUT (HTML)
# -----------------------------

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db=Depends(get_db),
):
    email_n = (email or "").strip().lower()
    user = db.query(User).filter(User.email == email_n).first()
    if not user or not user.is_active or not verify_password(password or "", user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=401)

    token = create_session(db, user.id)
    user.last_login_at = utc_now()
    db.commit()

    resp = RedirectResponse(url="/demo", status_code=303)
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
    user: User = Depends(require_user_html),
    db=Depends(get_db),
):
    ctx = {
        "advice_type": advice_type,
        "investment_element": (investment_element or "").lower() == "true",
        "ongoing_service": (ongoing_service or "").lower() == "true",
    }

    try:
        result = run_rules_engine(
            document_text=sr_text or "",
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

    run_id = persist_run(db, user, result, ctx, sr_text or "")
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
            elements.append(Paragraph("Suggested wording:", styles["Heading3"]))
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

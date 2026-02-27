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

app = FastAPI(title="Assure Compliance Engine")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

RULES_PATH = os.environ.get("RULES_PATH", "rules/cobs-mvp-v2.yaml")
SESSION_COOKIE = os.environ.get("ASSURE_SESSION_COOKIE", "assure_session")
COOKIE_SECURE = os.environ.get("ASSURE_COOKIE_SECURE", "true").lower() == "true"

BOOTSTRAP_EMAIL = os.environ.get("ASSURE_BOOTSTRAP_EMAIL", "").strip().lower()
BOOTSTRAP_PASSWORD = os.environ.get("ASSURE_BOOTSTRAP_PASSWORD", "")
BOOTSTRAP_FIRM = os.environ.get("ASSURE_BOOTSTRAP_FIRM", "Demo Firm")
APP_SECRET = os.environ.get("ASSURE_APP_SECRET", "")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def get_session_token_from_request(request: Request) -> str:
    return request.cookies.get(SESSION_COOKIE, "")


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

    return out


def persist_run(db, user: User, result: Dict[str, Any], context: Dict[str, Any], sr_text: str) -> str:
    run_id = str(uuid.uuid4())
    sr_hash = hashlib.sha256((sr_text or "").encode("utf-8")).hexdigest()

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
        summary_json=json.dumps(result.get("summary", {}), ensure_ascii=False),
        sections_json=json.dumps(result.get("sections", {}), ensure_ascii=False),
    )
    db.add(r)
    db.commit()
    return run_id


def _to_int_or_none(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s)
    except Exception:
        return None


def _build_context(
    *,
    advice_type: str,
    investment_element: Any,
    ongoing_service: Any,
    client_age: Optional[int],
    product_type: Optional[str],
) -> Dict[str, Any]:
    at = (advice_type or "").strip().lower() or "advised"
    pt = (product_type or "").strip().lower() or ""

    age_72_plus = bool(client_age is not None and client_age >= 72)

    return {
        "advice_type": at,
        "investment_element": bool(investment_element),
        "ongoing_service": bool(ongoing_service),
        "client_age_72_plus": age_72_plus,
        "product_type": pt,
    }


def ensure_bootstrap_admin(db) -> None:
    if not APP_SECRET:
        raise RuntimeError("ASSURE_APP_SECRET must be set in environment.")

    existing = db.query(User).first()
    if existing:
        return

    if not BOOTSTRAP_EMAIL or not BOOTSTRAP_PASSWORD:
        raise RuntimeError("No users exist yet. Set ASSURE_BOOTSTRAP_EMAIL and ASSURE_BOOTSTRAP_PASSWORD to create the first admin.")

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


class CheckRequest(BaseModel):
    advice_type: str
    document_text: str
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False
    client_age: Optional[int] = None
    product_type: Optional[str] = None


@app.post("/check")
async def check(payload: CheckRequest, request: Request, db=Depends(get_db)):
    user = get_user_by_session_token(db, get_session_token_from_request(request))
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    ctx = _build_context(
        advice_type=payload.advice_type,
        investment_element=bool(payload.investment_element),
        ongoing_service=bool(payload.ongoing_service),
        client_age=_to_int_or_none(payload.client_age),
        product_type=payload.product_type,
    )

    result = run_rules_engine(
        document_text=payload.document_text,
        context=ctx,
        rules_path=RULES_PATH,
    )

    run_id = persist_run(db, user, result, ctx, payload.document_text or "")
    result_out = dict(result)
    result_out["run_id"] = run_id
    result_out["completeness_pct"] = compute_completeness(result.get("summary", {}) or {})
    return JSONResponse(result_out)


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


@app.get("/demo", response_class=HTMLResponse)
def demo_get(request: Request, user: User = Depends(require_user_html)):
    return templates.TemplateResponse(
        "demo.html",
        {
            "request": request,
            "user_email": user.email,
            "defaults": {
                "advice_type": "advised",
                "investment_element": "true",
                "ongoing_service": "false",
                "client_age": "",
                "product_type": "",
            },
        },
    )


@app.post("/demo/run", response_class=HTMLResponse)
async def demo_run_post(
    request: Request,
    advice_type: str = Form(...),
    investment_element: str = Form("true"),
    ongoing_service: str = Form("false"),
    client_age: str = Form(""),
    product_type: str = Form(""),
    sr_text: str = Form(""),
    user: User = Depends(require_user_html),
    db=Depends(get_db),
):
    ctx = _build_context(
        advice_type=advice_type,
        investment_element=(investment_element or "").lower() == "true",
        ongoing_service=(ongoing_service or "").lower() == "true",
        client_age=_to_int_or_none(client_age),
        product_type=product_type,
    )

    result = run_rules_engine(
        document_text=sr_text or "",
        context=ctx,
        rules_path=RULES_PATH,
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

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "run_id": run_id,
            "result": result,
            "summary": summary,
            "completeness_pct": completeness_pct,
            "action_items": action_items,
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

    action_items = extract_action_items(result)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    elements: List[Any] = []

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    h3 = styles["Heading3"]

    elements.append(Paragraph("Assure Compliance Report", h1))
    elements.append(Spacer(1, 0.3 * inch))

    summary = result.get("summary", {})
    elements.append(Paragraph(f"OK: {summary.get('ok', 0)}", normal))
    elements.append(Paragraph(f"Issues: {summary.get('potential_issue', 0)}", normal))
    elements.append(Spacer(1, 0.3 * inch))

    for item in action_items:
        elements.append(Paragraph(item.get("title", "Issue"), h2))
        elements.append(Spacer(1, 0.1 * inch))

        elements.append(Paragraph("What to fix:", h3))
        fixes = [ListItem(Paragraph(str(f), normal)) for f in (item.get("fixes") or [])]
        if fixes:
            elements.append(ListFlowable(fixes, bulletType="bullet"))

        suggestions = item.get("suggestions") or []
        if suggestions:
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph("Suggested wording:", h3))
            sug = [ListItem(Paragraph(str(s), normal)) for s in suggestions]
            elements.append(ListFlowable(sug, bulletType="bullet"))

        elements.append(Spacer(1, 0.4 * inch))

    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=assure-run-{run_id}.pdf"},
    )


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
    users = db.query(User).filter(User.firm_id == user.firm_id).all()

    if not email_clean:
        return templates.TemplateResponse(
            "users.html",
            {"request": request, "users": users, "error": "Email is required"},
            status_code=400,
        )

    existing = db.query(User).filter(User.email == email_clean, User.firm_id == user.firm_id).first()
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


@app.get("/health")
def health():
    safe_db = None
    if DB_URL:
        safe_db = DB_URL.split("@")[-1]
    return {
        "status": "ok",
        "rules_path": RULES_PATH,
        "db": safe_db,
        "db_driver": "sqlite" if (DB_URL or "").startswith("sqlite") else "postgres",
    }


@app.get("/", response_class=PlainTextResponse)
def root():
    return "Assure is running. Visit /login"
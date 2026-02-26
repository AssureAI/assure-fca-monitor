from __future__ import annotations

import os
import json
import uuid
import hashlib
from typing import Dict, Optional, Any

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from pydantic import BaseModel
from datetime import datetime, timezone

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
)

# -----------------------------
# APP
# -----------------------------

app = FastAPI(title="Assure Compliance Engine")

templates = Jinja2Templates(directory="templates")

# Mount static files AFTER app exists
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="static"), name="static")

RULES_PATH = os.environ.get("RULES_PATH", "rules/cobs-mvp-v2.yaml")

# Cookie name for sessions
SESSION_COOKIE = os.environ.get("ASSURE_SESSION_COOKIE", "assure_session")

# If you deploy behind HTTPS (Render), keep secure cookies on.
COOKIE_SECURE = os.environ.get("ASSURE_COOKIE_SECURE", "true").lower() == "true"

# Bootstrap (first admin user)
BOOTSTRAP_EMAIL = os.environ.get("ASSURE_BOOTSTRAP_EMAIL", "").strip().lower()
BOOTSTRAP_PASSWORD = os.environ.get("ASSURE_BOOTSTRAP_PASSWORD", "")
BOOTSTRAP_FIRM = os.environ.get("ASSURE_BOOTSTRAP_FIRM", "Demo Firm")

# Used to sign/validate sensitive flows later; for now it’s a “must set”.
APP_SECRET = os.environ.get("ASSURE_APP_SECRET", "")

if not APP_SECRET:
    # Don’t hard fail import-time in local dev; we’ll enforce at startup.
    pass


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
# AUTH HELPERS
# -----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_session_token_from_request(request: Request) -> str:
    return request.cookies.get(SESSION_COOKIE, "")


def require_user(request: Request, db=Depends(get_db)) -> User:
    token = get_session_token_from_request(request)
    user = get_user_by_session_token(db, token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_user_html(request: Request, db=Depends(get_db)) -> User:
    token = get_session_token_from_request(request)
    user = get_user_by_session_token(db, token)
    if not user:
        # Redirect for browser pages
        raise HTTPException(status_code=401, detail="LOGIN_REQUIRED")
    return user


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Special-case our HTML auth redirect
    if exc.status_code == 401 and exc.detail == "LOGIN_REQUIRED":
        return RedirectResponse(url="/login", status_code=303)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


# -----------------------------
# BOOTSTRAP
# -----------------------------

def ensure_bootstrap_admin(db) -> None:
    """
    Ensures there is at least one firm + admin user.
    Controlled by ASSURE_BOOTSTRAP_* env vars.
    """
    if not APP_SECRET:
        raise RuntimeError("ASSURE_APP_SECRET must be set in environment.")

    # If any user exists, we assume bootstrap already done.
    existing = db.query(User).first()
    if existing:
        return

    if not BOOTSTRAP_EMAIL or not BOOTSTRAP_PASSWORD:
        raise RuntimeError(
            "No users exist yet. Set ASSURE_BOOTSTRAP_EMAIL and ASSURE_BOOTSTRAP_PASSWORD to create the first admin."
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

    # Persist firm-scoped run
    run_id = str(uuid.uuid4())
    sr_text = payload.document_text or ""
    sr_hash = hashlib.sha256(sr_text.encode("utf-8")).hexdigest()
    r = Run(
        id=run_id,
        firm_id=user.firm_id,
        user_id=user.id,
        ruleset_id=result.get("ruleset_id") or "",
        ruleset_version=result.get("ruleset_version") or "",
        checked_at=result.get("checked_at") or utc_now_iso(),
        advice_type=str(context["advice_type"]),
        investment_element="true" if bool(context["investment_element"]) else "false",
        ongoing_service="true" if bool(context["ongoing_service"]) else "false",
        sr_hash=sr_hash,
        sr_len=len(sr_text),
        summary_json=json.dumps(result.get("summary", {}), ensure_ascii=False),
        sections_json=json.dumps(result.get("sections", {}), ensure_ascii=False),
    )
    db.add(r)
    db.commit()

    # Return result + run_id so UI can link to it later
    result_out = dict(result)
    result_out["run_id"] = run_id
    return JSONResponse(result_out)


# -----------------------------
# LOGIN / LOGOUT (HTML)
# -----------------------------

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    # If you have a template, use it. If not, this still works.
    try:
        return templates.TemplateResponse("login.html", {"request": request, "error": None})
    except Exception:
        html = """
        <html><body style="font-family:system-ui;max-width:520px;margin:40px auto;">
          <h2>Login</h2>
          <form method="post">
            <label>Email</label><br/>
            <input name="email" type="email" style="width:100%;padding:8px" /><br/><br/>
            <label>Password</label><br/>
            <input name="password" type="password" style="width:100%;padding:8px" /><br/><br/>
            <button style="padding:10px 14px">Login</button>
          </form>
        </body></html>
        """
        return HTMLResponse(html)


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
        # Template if exists, else fallback HTML
        try:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
        except Exception:
            return HTMLResponse("<h3>Invalid credentials</h3><a href='/login'>Try again</a>", status_code=401)

    token = create_session(db, user.id)
    user.last_login_at = datetime.now(timezone.utc).replace(microsecond=0)
    db.commit()

    resp = RedirectResponse(url="/admin/test", status_code=303)
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


@app.post("/logout")
def logout(request: Request, db=Depends(get_db)):
    token = get_session_token_from_request(request)
    if token:
        delete_session(db, token)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# -----------------------------
# ADMIN UI (AUTHED)
# -----------------------------

@app.get("/admin/test", response_class=HTMLResponse)
def admin_test_get(request: Request, user: User = Depends(require_user_html)):
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
            "user_email": user.email,
            "firm_id": user.firm_id,
        },
    )


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_post(
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

    result = run_rules_engine(
        document_text=sr_text or "",
        context=ctx,
        rules_path=RULES_PATH,
    )

    run_id = str(uuid.uuid4())
    text = sr_text or ""
    sr_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    r = Run(
        id=run_id,
        firm_id=user.firm_id,
        user_id=user.id,
        ruleset_id=result.get("ruleset_id") or "",
        ruleset_version=result.get("ruleset_version") or "",
        checked_at=result.get("checked_at") or utc_now_iso(),
        advice_type=advice_type,
        investment_element="true" if ctx["investment_element"] else "false",
        ongoing_service="true" if ctx["ongoing_service"] else "false",
        sr_hash=sr_hash,
        sr_len=len(text),
        summary_json=json.dumps(result.get("summary", {}), ensure_ascii=False),
        sections_json=json.dumps(result.get("sections", {}), ensure_ascii=False),
    )
    db.add(r)
    db.commit()

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
            "user_email": user.email,
            "firm_id": user.firm_id,
        },
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
    for r in rows:
        runs.append(
            {
                "id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "ruleset_id": r.ruleset_id,
                "ruleset_version": r.ruleset_version,
                "checked_at": r.checked_at,
                "summary": json.loads(r.summary_json or "{}"),
            }
        )

    return templates.TemplateResponse(
        "runs.html",
        {"request": request, "runs": runs, "user_email": user.email, "firm_id": user.firm_id},
    )


@app.get("/admin/runs/{run_id}", response_class=HTMLResponse)
def admin_run_detail(request: Request, run_id: str, user: User = Depends(require_user_html), db=Depends(get_db)):
    r = db.query(Run).filter(Run.id == run_id, Run.firm_id == user.firm_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Run not found")

    run = {
        "id": r.id,
        "created_at": r.created_at.isoformat() if r.created_at else "",
        "ruleset_id": r.ruleset_id,
        "ruleset_version": r.ruleset_version,
        "checked_at": r.checked_at,
        "summary": json.loads(r.summary_json or "{}"),
        "sections": json.loads(r.sections_json or "{}"),
        "advice_type": r.advice_type,
        "investment_element": r.investment_element,
        "ongoing_service": r.ongoing_service,
        "sr_hash": r.sr_hash,
        "sr_len": r.sr_len,
    }

    return templates.TemplateResponse(
        "run_detail.html",
        {"request": request, "run": run, "user_email": user.email, "firm_id": user.firm_id},
    )


# -----------------------------
# HEALTH
# -----------------------------

@app.get("/health")
def health():
    from database import DB_URL
    return {
        "status": "ok",
        "rules_path": RULES_PATH,
        "db": DB_URL.split("@")[-1] if DB_URL else None,  # hides creds
        "db_driver": "sqlite" if (DB_URL or "").startswith("sqlite") else "postgres",
    }


# Optional: make "/" not 404 so Render health checks look nicer
@app.get("/", response_class=PlainTextResponse)
def root():
    return "Assure is running. Visit /login"

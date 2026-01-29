from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Literal
from datetime import datetime
import os
import re
import hmac
import hashlib

import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from bs4 import BeautifulSoup

# -----------------------------
# CONFIG (FCA monitor)
# -----------------------------

COBS_URLS: Dict[str, str] = {
    "COBS 2":  "https://handbook.fca.org.uk/handbook/COBS/2/3.html",
    "COBS 3":  "https://handbook.fca.org.uk/handbook/COBS/3/5.html",
    "COBS 4":  "https://handbook.fca.org.uk/handbook/COBS/4/",
    "COBS 6":  "https://handbook.fca.org.uk/handbook/COBS/6/",
    "COBS 9":  "https://handbook.fca.org.uk/handbook/COBS/9/",
    "COBS 9.3": "https://handbook.fca.org.uk/handbook/COBS/9/3.html",
    "COBS 13.2": "https://handbook.fca.org.uk/handbook/COBS/13/2.html",
    "COBS 16.3": "https://handbook.fca.org.uk/handbook/COBS/16/3.html",
    "COBS 22": "https://handbook.fca.org.uk/handbook/COBS/22/",
}

DATABASE_URL = os.environ.get("DATABASE_URL")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")  # optional
INGEST_TOKEN = os.environ.get("INGEST_TOKEN")  # used later if you want to lock down endpoints

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

# -----------------------------
# APP SETUP
# -----------------------------

app = FastAPI(title="Assure FCA monitor + rules engine")

if not os.path.isdir("templates"):
    os.makedirs("templates", exist_ok=True)
if not os.path.isdir("static"):
    os.makedirs("static", exist_ok=True)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


def get_conn():
    # Render Postgres requires SSL; DATABASE_URL from Render usually includes sslmode.
    # If yours doesn't, append '?sslmode=require' in the env var.
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


# -----------------------------
# FCA MONITOR HELPERS
# -----------------------------

def extract_last_updated_date(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n", strip=True)

    date_pat = re.compile(r"(\d{2})/(\d{2})/(\d{4})")
    for line in text.splitlines():
        if "updated" in line.lower():
            m = date_pat.search(line)
            if m:
                d, mth, y = m.groups()
                return f"{y}-{mth}-{d}"

    m = date_pat.search(text)
    if m:
        d, mth, y = m.groups()
        return f"{y}-{mth}-{d}"

    return None


def fetch_fca_date(module: str) -> Optional[str]:
    url = COBS_URLS[module]
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return extract_last_updated_date(resp.text)


def notify_slack(message: str):
    if not SLACK_WEBHOOK_URL:
        return
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=10)
    except Exception as e:
        print(f"Error sending Slack notification: {e}")


def run_fca_check():
    print("[FCA monitor] Running FCA COBS check...")
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            for module, url in COBS_URLS.items():
                try:
                    fca_date_str = fetch_fca_date(module)
                except Exception as e:
                    print(f"[FCA monitor] Error fetching {module} from FCA: {e}")
                    continue

                if not fca_date_str:
                    print(f"[FCA monitor] No 'last updated' date found for {module}")
                    continue

                cur.execute(
                    """
                    SELECT *
                      FROM fca_cobs_updates
                     WHERE module = %s
                     ORDER BY new_date DESC
                     LIMIT 1
                    """,
                    (module,),
                )
                latest = cur.fetchone()

                fca_date = datetime.strptime(fca_date_str, "%Y-%m-%d").date()

                if latest is None:
                    cur.execute(
                        """
                        INSERT INTO fca_cobs_updates (module, url, old_date, new_date)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (module, url, None, fca_date),
                    )
                    conn.commit()
                    print(f"[FCA monitor] Initial record for {module}: {fca_date}")
                    continue

                latest_date = latest["new_date"]
                if fca_date != latest_date:
                    cur.execute(
                        """
                        INSERT INTO fca_cobs_updates (module, url, old_date, new_date)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (module, url, latest_date, fca_date),
                    )
                    conn.commit()

                    message = (
                        f"FCA COBS update detected for {module}:\n"
                        f"- Old date: {latest_date}\n"
                        f"- New date: {fca_date}\n"
                        f"- URL: {url}"
                    )
                    print("[FCA monitor]", message)
                    notify_slack(message)

        print("[FCA monitor] Check complete.")
    finally:
        conn.close()


# -----------------------------
# RULES ENGINE (what Base44 needs)
# -----------------------------

Status = Literal["OK", "POTENTIAL_ISSUE", "NOT_ASSESSED"]

class CheckRequest(BaseModel):
    advice_type: str = Field(..., description="e.g. advised / execution_only / standard")
    filename: Optional[str] = None
    document_text: str = Field(..., min_length=1)

class RuleResult(BaseModel):
    rule_id: str
    status: Status
    citation: str
    source_url: str
    excerpt: Optional[str] = None  # keep null by default

class CheckResponse(BaseModel):
    ruleset_version: str
    checked_at: str
    summary: Dict[str, int]
    results: List[RuleResult]


RULESET_VERSION = "cobs-sr-v0.1"

def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()

def _contains_any(text: str, phrases: List[str]) -> bool:
    t = _norm(text)
    return any(p.lower() in t for p in phrases)

def run_deterministic_rules(advice_type: str, document_text: str) -> List[RuleResult]:
    """
    V1 rules: simple, defensible presence/absence checks.
    Return ONLY: OK / POTENTIAL_ISSUE / NOT_ASSESSED
    """
    t = document_text or ""
    at = (advice_type or "").lower().strip()

    results: List[RuleResult] = []

    # Example rule set (small and safe). We can expand later.
    # 1) Risk profiling present
    results.append(RuleResult(
        rule_id="SR_RISK_PROFILE_PRESENT",
        status="OK" if _contains_any(t, ["risk profile", "attitude to risk", "risk questionnaire"]) else "POTENTIAL_ISSUE",
        citation="COBS 9.2.2R",
        source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
        excerpt=None
    ))

    # 2) Capacity for loss referenced
    results.append(RuleResult(
        rule_id="SR_CAPACITY_FOR_LOSS_PRESENT",
        status="OK" if _contains_any(t, ["capacity for loss", "loss capacity"]) else "POTENTIAL_ISSUE",
        citation="COBS 9.2.2R",
        source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
        excerpt=None
    ))

    # 3) Costs/charges referenced
    results.append(RuleResult(
        rule_id="SR_COSTS_CHARGES_PRESENT",
        status="OK" if _contains_any(t, ["cost", "charge", "fee", "ongoing charges figure", "ocf"]) else "POTENTIAL_ISSUE",
        citation="COBS 6.1ZA / COBS 6.1ZB (cost disclosure obligations vary by context)",
        source_url="https://handbook.fca.org.uk/handbook/COBS/6/",
        excerpt=None
    ))

    # 4) Recommendation suitability language (only applicable if advice_type suggests advised)
    if at in ("advised", "standard", "financial_advice"):
        results.append(RuleResult(
            rule_id="SR_SUITABILITY_RECOMMENDATION_PRESENT",
            status="OK" if _contains_any(t, ["we recommend", "recommendation", "suitable", "suitability"]) else "POTENTIAL_ISSUE",
            citation="COBS 9.2.1R",
            source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
            excerpt=None
        ))
    else:
        results.append(RuleResult(
            rule_id="SR_SUITABILITY_RECOMMENDATION_PRESENT",
            status="NOT_ASSESSED",
            citation="COBS 9.2.1R",
            source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
            excerpt=None
        ))

    # 5) Basic client objectives / needs
    results.append(RuleResult(
        rule_id="SR_OBJECTIVES_NEEDS_PRESENT",
        status="OK" if _contains_any(t, ["objectives", "needs", "goals", "your goal", "your objectives"]) else "POTENTIAL_ISSUE",
        citation="COBS 9.2.2R",
        source_url="https://handbook.fca.org.uk/handbook/COBS/9/2.html",
        excerpt=None
    ))

    return results


@app.post("/check")
def check(req: CheckRequest):
    # No DB writes. Pure evaluation.
    results = run_deterministic_rules(req.advice_type, req.document_text)

    ok = sum(1 for r in results if r.status == "OK")
    potential = sum(1 for r in results if r.status == "POTENTIAL_ISSUE")
    not_assessed = sum(1 for r in results if r.status == "NOT_ASSESSED")

    payload = CheckResponse(
        ruleset_version=RULESET_VERSION,
        checked_at=datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        summary={"ok": ok, "potential_issue": potential, "not_assessed": not_assessed},
        results=results
    )
    return JSONResponse(payload.model_dump())


# -----------------------------
# EXISTING ROUTES
# -----------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.api_route("/cron/run-check", methods=["GET", "POST"])
def cron_run_check():
    run_fca_check()
    return {"ok": True}


@app.get("/admin/updates", response_class=HTMLResponse)
def admin_updates(request: Request):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                  FROM fca_cobs_updates
                 ORDER BY detected_at DESC
                 LIMIT 100
                """
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return templates.TemplateResponse("admin_updates.html", {"request": request, "updates": rows})


@app.post("/admin/updates/{update_id}/review")
def mark_reviewed(update_id: int, reviewer: str = Form(default="Assure.ai")):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE fca_cobs_updates
                   SET reviewed = TRUE,
                       reviewed_at = now(),
                       reviewer = %s
                 WHERE id = %s
                """,
                (reviewer, update_id),
            )
            conn.commit()
    finally:
        conn.close()

    return RedirectResponse(url="/admin/updates", status_code=303)

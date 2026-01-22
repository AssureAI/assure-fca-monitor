from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
import os
import hmac

import requests
import psycopg2
from psycopg2.extras import RealDictCursor

# ---------- CONFIG ----------

# Keep this list as the "canonical" modules you track.
# (These URLs will be used in the dashboard and also to validate ingested items.)
COBS_URLS: Dict[str, str] = {
    "COBS 2":   "https://handbook.fca.org.uk/handbook/COBS/2/3.html",
    "COBS 3":   "https://handbook.fca.org.uk/handbook/COBS/3/5.html",
    "COBS 4":   "https://handbook.fca.org.uk/handbook/COBS/4/1.html",
    "COBS 6":   "https://handbook.fca.org.uk/handbook/COBS/6/1.html",
    "COBS 9":   "https://handbook.fca.org.uk/handbook/COBS/9/1.html",
    "COBS 9.3": "https://handbook.fca.org.uk/handbook/COBS/9/3.html",
    "COBS 13.2":"https://handbook.fca.org.uk/handbook/COBS/13/2.html",
    "COBS 16.3":"https://handbook.fca.org.uk/handbook/COBS/16/3.html",
    "COBS 22":  "https://handbook.fca.org.uk/handbook/COBS/22/1.html",
}

DATABASE_URL = os.environ.get("DATABASE_URL")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")  # optional
INGEST_TOKEN = os.environ.get("INGEST_TOKEN")            # required (secure ingestion)

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

if not INGEST_TOKEN:
    raise RuntimeError("INGEST_TOKEN environment variable is required")

# ---------- APP SETUP ----------

app = FastAPI(title="Assure FCA monitor")

if not os.path.isdir("templates"):
    os.makedirs("templates", exist_ok=True)
if not os.path.isdir("static"):
    os.makedirs("static", exist_ok=True)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------- DB ----------

def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# ---------- SECURITY ----------

def require_ingest_token(token: str):
    # constant-time compare to avoid timing leaks
    if not hmac.compare_digest(token or "", INGEST_TOKEN or ""):
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------- MODELS ----------

class UpdateItem(BaseModel):
    module: str
    url: str
    last_updated: str  # YYYY-MM-DD

class BatchPayload(BaseModel):
    items: List[UpdateItem]

# ---------- NOTIFICATIONS ----------

def notify_slack(message: str):
    if not SLACK_WEBHOOK_URL:
        return
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=10)
    except Exception as e:
        print(f"Error sending Slack notification: {e}")

# ---------- ROUTES ----------

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/ingest/batch")
def ingest_batch(payload: BatchPayload, token: str = ""):
    """
    Called by GitHub Actions (Playwright scraper).
    - Validates token
    - Inserts initial baseline rows (no Slack)
    - Inserts change rows (optional Slack)
    """
    require_ingest_token(token)

    conn = get_conn()
    inserted = 0
    changed = 0
    ignored = 0

    try:
        with conn.cursor() as cur:
            for item in payload.items:
                # Only allow known modules
                if item.module not in COBS_URLS:
                    ignored += 1
                    continue

                # Trust our canonical URL list, but store the provided URL if you want:
                # url_to_store = item.url
                url_to_store = COBS_URLS[item.module]

                # Parse date
                try:
                    fca_date = datetime.strptime(item.last_updated, "%Y-%m-%d").date()
                except ValueError:
                    ignored += 1
                    continue

                # Latest record for this module
                cur.execute(
                    """
                    SELECT *
                      FROM fca_cobs_updates
                     WHERE module = %s
                     ORDER BY new_date DESC
                     LIMIT 1
                    """,
                    (item.module,),
                )
                latest = cur.fetchone()

                if latest is None:
                    # Baseline entry (first time we ever recorded it)
                    cur.execute(
                        """
                        INSERT INTO fca_cobs_updates (module, url, old_date, new_date)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (item.module, url_to_store, None, fca_date),
                    )
                    inserted += 1
                    continue

                latest_date = latest["new_date"]

                if fca_date != latest_date:
                    cur.execute(
                        """
                        INSERT INTO fca_cobs_updates (module, url, old_date, new_date)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (item.module, url_to_store, latest_date, fca_date),
                    )
                    inserted += 1
                    changed += 1

                    notify_slack(
                        "FCA COBS update detected:\n"
                        f"- Module: {item.module}\n"
                        f"- Old date: {latest_date}\n"
                        f"- New date: {fca_date}\n"
                        f"- URL: {url_to_store}"
                    )

            conn.commit()

    finally:
        conn.close()

    return {"ok": True, "inserted": inserted, "changed": changed, "ignored": ignored}

@app.get("/admin/updates", response_class=HTMLResponse)
def admin_updates(request: Request):
    """
    Internal dashboard: list recent updates.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                  FROM fca_cobs_updates
                 ORDER BY detected_at DESC
                 LIMIT 200
                """
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    return templates.TemplateResponse(
        "admin_updates.html",
        {"request": request, "updates": rows},
    )

@app.post("/admin/updates/{update_id}/review")
def mark_reviewed(update_id: int, reviewer: str = Form(default="Assure.ai")):
    """
    Mark an update as reviewed.
    """
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

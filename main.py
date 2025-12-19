from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from typing import Optional, Dict
from datetime import datetime
import os
import re

import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from bs4 import BeautifulSoup

# ---------- CONFIG ----------

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

DATE_RE = re.compile(r"last updated on (\d{2})/(\d{2})/(\d{4})", re.IGNORECASE)

DATABASE_URL = os.environ.get("DATABASE_URL")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")  # optional

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

# ---------- APP SETUP ----------

app = FastAPI(title="Assure FCA monitor")

if not os.path.isdir("templates"):
    os.makedirs("templates", exist_ok=True)
if not os.path.isdir("static"):
    os.makedirs("static", exist_ok=True)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def extract_last_updated_date(html: str) -> Optional[str]:
    """
    Robustly find the last updated date from FCA handbook pages.
    FCA wording/layout varies, so we:
    1) Look for lines containing 'updated' and a DD/MM/YYYY date
    2) Fallback: look for ANY DD/MM/YYYY date on the page and take the latest by position
    Returns 'YYYY-MM-DD' or None.
    """
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n", strip=True)

    # 1) Preferred: find a line that mentions 'updated' and contains a date
    date_pat = re.compile(r"(\d{2})/(\d{2})/(\d{4})")
    for line in text.splitlines():
        if "updated" in line.lower():
            m = date_pat.search(line)
            if m:
                d, mth, y = m.groups()
                return f"{y}-{mth}-{d}"

    # 2) Fallback: any DD/MM/YYYY anywhere (take the first match as a baseline)
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


def run_check():
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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.api_route("/cron/run-check", methods=["GET", "POST"])
def cron_run_check():
    run_check()
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

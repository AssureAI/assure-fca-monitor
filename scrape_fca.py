import os
import re
import sys
import requests
from playwright.sync_api import sync_playwright

COBS_URLS = {
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

# FCA text normally looks like: "was last updated on 03/01/2018"
DATE_RE = re.compile(r"last updated on (\d{2})/(\d{2})/(\d{4})", re.IGNORECASE)

ASSURE_INGEST_URL = os.environ["ASSURE_INGEST_URL"].rstrip("/")  # e.g. https://assure-fca-monitor.onrender.com
INGEST_TOKEN = os.environ["INGEST_TOKEN"]

def extract_date_from_text(text: str):
    m = DATE_RE.search(text)
    if not m:
        return None
    dd, mm, yyyy = m.groups()
    return f"{yyyy}-{mm}-{dd}"

def main():
    items = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        for module, url in COBS_URLS.items():
            print(f"Visiting {module} -> {url}")
            page.goto(url, wait_until="networkidle", timeout=90000)
            body_text = page.inner_text("body")

            iso = extract_date_from_text(body_text)
            if not iso:
                print(f"[WARN] No 'last updated' date found for {module}", file=sys.stderr)
                continue

            print(f"[OK] {module}: {iso}")
            items.append({"module": module, "url": url, "last_updated": iso})

        browser.close()

    if not items:
        print("[ERROR] Extracted 0 items. Aborting ingest.", file=sys.stderr)
        sys.exit(1)

    r = requests.post(
        f"{ASSURE_INGEST_URL}/ingest/batch",
        params={"token": INGEST_TOKEN},
        json={"items": items},
        timeout=60,
    )

    print("Ingest HTTP:", r.status_code)
    print(r.text)
    r.raise_for_status()

if __name__ == "__main__":
    main()

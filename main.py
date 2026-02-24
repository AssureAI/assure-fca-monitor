from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
from typing import Dict, Optional

from executor import run_rules_engine

app = FastAPI(title="Assure Deterministic Compliance Engine")


# --------------------------------------------------
# REQUEST MODEL
# --------------------------------------------------

class CheckRequest(BaseModel):
    advice_type: str = Field(..., description="advised / standard / execution_only / nonadvised")
    document_text: str = Field(..., min_length=1)
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False


RULES_PATH = "rules/cobs-suitability-v1.yaml"


# --------------------------------------------------
# CORE API
# --------------------------------------------------

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


# --------------------------------------------------
# ADMIN UI
# --------------------------------------------------

@app.get("/admin/test", response_class=HTMLResponse)
def admin_test():
    return """
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body { font-family: Arial, sans-serif; max-width: 1100px; margin: 24px; }
        textarea { width: 100%; height: 260px; font-family: ui-monospace, Menlo, Consolas, monospace; }
        select, button { padding: 10px; }
        .row { display: flex; gap: 14px; flex-wrap: wrap; align-items: center; margin: 10px 0; }
        .btn { background: #111827; color: #fff; border: 0; border-radius: 8px; cursor: pointer; padding: 10px 14px; }
        .btn:hover { opacity: 0.92; }
        .muted { color: #666; }
      </style>
    </head>
    <body>
      <h1>Assure – Admin Test</h1>
      <p class="muted">Deterministic check. Results grouped by section. Evidence is capped snippets (no full SR echo).</p>

      <form method="post">
        <div class="row">
          <div>
            <label><b>Advice type</b></label><br/>
            <select name="advice_type">
              <option value="advised" selected>advised</option>
              <option value="standard">standard</option>
              <option value="execution_only">execution_only</option>
              <option value="nonadvised">nonadvised</option>
            </select>
          </div>

          <div>
            <label><b>Investment element</b></label><br/>
            <select name="investment_element">
              <option value="true" selected>true</option>
              <option value="false">false</option>
            </select>
          </div>

          <div>
            <label><b>Ongoing service</b></label><br/>
            <select name="ongoing_service">
              <option value="false" selected>false</option>
              <option value="true">true</option>
            </select>
          </div>
        </div>

        <label><b>Suitability Report text</b></label><br/>
        <textarea name="document_text" placeholder="Paste SR text here..."></textarea><br/><br/>

        <button class="btn" type="submit">Run check</button>
      </form>
    </body>
    </html>
    """


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_run(
    advice_type: str = Form(...),
    investment_element: str = Form("true"),
    ongoing_service: str = Form("false"),
    document_text: str = Form(...),
):
    inv = (investment_element or "").lower() == "true"
    ong = (ongoing_service or "").lower() == "true"

    context: Dict[str, object] = {
        "advice_type": advice_type,
        "investment_element": bool(inv),
        "ongoing_service": bool(ong),
    }

    result = run_rules_engine(
        document_text=document_text,
        context=context,
        rules_path=RULES_PATH,
    )

    # Accordion HTML
    def badge(n: int, label: str) -> str:
        return f"<span style='display:inline-block;padding:2px 8px;border:1px solid #ddd;border-radius:999px;margin-left:8px;color:#111'>{label}: {n}</span>"

    sections_html = ""
    for sec in result.get("sections", []):
        sname = sec.get("section", "Unsorted")
        summ = sec.get("summary", {})
        rules = sec.get("rules", [])

        header = (
            f"{sname}"
            f"{badge(int(summ.get('ok',0)), 'OK')}"
            f"{badge(int(summ.get('potential_issue',0)), 'PI')}"
            f"{badge(int(summ.get('not_assessed',0)), 'NA')}"
        )

        rows = ""
        for r in rules:
            st = r.get("status", "")
            color = "#0a7b34" if st == "OK" else "#b26a00" if st == "POTENTIAL_ISSUE" else "#666"
            ev = r.get("evidence", {}) or {}
            snippets = ev.get("snippets", []) if isinstance(ev, dict) else []
            snippets = snippets if isinstance(snippets, list) else []
            # render snippets as bullets
            snip_html = ""
            if snippets:
                snip_html = "<ul>" + "".join(f"<li>{_escape(x)}</li>" for x in snippets) + "</ul>"
            else:
                snip_html = "<span style='color:#666'>No snippet evidence captured.</span>"

            src = r.get("source_url") or ""
            src_html = f"<a href='{src}' target='_blank'>{src}</a>" if src else "<span style='color:#666'>n/a</span>"

            rows += f"""
              <div style="border:1px solid #eee;border-radius:10px;padding:12px;margin:10px 0;">
                <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;">
                  <div><b>{_escape(r.get("rule_id",""))}</b> — {_escape(r.get("title",""))}</div>
                  <div style="font-weight:700;color:{color};">{st}</div>
                </div>
                <div style="margin-top:6px;color:#111;">
                  <div><b>Citation:</b> {_escape(r.get("citation",""))}</div>
                  <div><b>Source:</b> {src_html}</div>
                  <div style="margin-top:8px;"><b>Evidence snippets:</b> {snip_html}</div>
                </div>
              </div>
            """

        sections_html += f"""
          <details style="border:1px solid #ddd;border-radius:12px;padding:12px;margin:12px 0;">
            <summary style="cursor:pointer;font-weight:800;">{header}</summary>
            <div style="margin-top:10px;">{rows}</div>
          </details>
        """

    summary = result.get("summary", {})
    return f"""
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body {{ font-family: Arial, sans-serif; max-width: 1100px; margin: 24px; }}
        pre {{ background:#0b1020;color:#e5e7eb;padding:12px;border-radius:10px;overflow:auto; }}
        a {{ color:#2563eb; }}
        .muted {{ color:#666; }}
      </style>
    </head>
    <body>
      <h1>Results</h1>
      <p><a href="/admin/test">Run again</a></p>

      <p class="muted"><b>Ruleset:</b> {_escape(result.get("ruleset_id",""))} v{_escape(result.get("ruleset_version",""))} — <b>Checked:</b> {_escape(result.get("checked_at",""))}</p>
      <div style="border:1px solid #ddd;border-radius:12px;padding:12px;">
        <b>Summary</b>
        <pre>{_escape(str(summary))}</pre>
      </div>

      <h2 style="margin-top:18px;">Sections</h2>
      {sections_html}

      <h2 style="margin-top:18px;">Raw JSON (debug)</h2>
      <pre>{_escape(str(result))}</pre>
    </body>
    </html>
    """


def _escape(s: str) -> str:
    s = str(s)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#039;")
    )


@app.get("/health")
def health():
    return {"status": "ok"}

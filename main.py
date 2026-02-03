from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from typing import Dict, Optional

from executor import run_rules_engine, EXECUTOR_VERSION

app = FastAPI(title="Assure Deterministic Compliance Engine")


class CheckRequest(BaseModel):
    advice_type: str
    document_text: str
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False


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
        rules_path="rules/cobs-suitability-v1.yaml",
    )
    return JSONResponse(result)


@app.get("/admin/test", response_class=HTMLResponse)
def admin_test():
    return """
    <html>
      <head>
        <title>Assure Admin Test</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body { font-family: Arial, sans-serif; margin: 24px; max-width: 1100px; }
          textarea { width: 100%; height: 280px; font-family: ui-monospace, Menlo, Consolas, monospace; }
          select, button { padding: 8px; }
          .row { display:flex; gap:16px; flex-wrap:wrap; align-items:center; margin: 10px 0; }
          .btn { padding: 10px 14px; border: 0; border-radius: 8px; background: #111827; color: #fff; cursor: pointer; }
          .btn:hover { opacity: 0.92; }
        </style>
      </head>
      <body>
        <h1>Assure Admin Test</h1>
        <div style="color:#666;">Executor: """ + EXECUTOR_VERSION + """</div>

        <form method="post">
          <div class="row">
            <div>
              <label>Advice type</label><br/>
              <select name="advice_type">
                <option value="advised" selected>advised</option>
                <option value="standard">standard</option>
                <option value="execution_only">execution_only</option>
              </select>
            </div>

            <div>
              <label>Investment element</label><br/>
              <select name="investment_element">
                <option value="true" selected>true</option>
                <option value="false">false</option>
              </select>
            </div>

            <div>
              <label>Ongoing service</label><br/>
              <select name="ongoing_service">
                <option value="false" selected>false</option>
                <option value="true">true</option>
              </select>
            </div>
          </div>

          <div class="row">
            <div style="flex:1;">
              <label>Suitability report text</label><br/>
              <textarea name="document_text" placeholder="Paste SR text here..."></textarea>
            </div>
          </div>

          <div class="row">
            <button class="btn" type="submit">Run check</button>
          </div>
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
    context: Dict[str, object] = {
        "advice_type": advice_type,
        "investment_element": (investment_element or "").lower() == "true",
        "ongoing_service": (ongoing_service or "").lower() == "true",
    }

    try:
        result = run_rules_engine(
            document_text=document_text,
            context=context,
            rules_path="rules/cobs-suitability-v1.yaml",
        )
    except Exception as e:
        return HTMLResponse(
            f"""
            <html><body style="font-family:Arial;margin:24px;max-width:1100px;">
              <h1>Ruleset/Executor error</h1>
              <pre style="white-space:pre-wrap;background:#f7f7f7;padding:12px;border-radius:8px;">{str(e)}</pre>
              <p><a href="/admin/test">Back</a></p>
            </body></html>
            """,
            status_code=200,
        )

    summary = result.get("summary", {"ok": 0, "potential_issue": 0, "not_assessed": 0})
    ruleset_id = result.get("ruleset_id", "")
    ruleset_ver = result.get("ruleset_version", "")
    checked_at = result.get("checked_at", "")

    # Accordion sections – ALWAYS from result["sections"]
    sections = result.get("sections", [])
    sections_html = ""

    for sec in sections:
        sec_title = sec.get("section_title", sec.get("section_id", ""))
        rules = sec.get("rules", [])

        # Render each rule with an inner details for evidence
        rules_rows = ""
        for r in rules:
            rid = r.get("rule_id", "")
            st = r.get("status", "")
            cit = r.get("citation", "")
            ev = (r.get("evidence") or {})
            ev_sents = ev.get("sentences", []) if isinstance(ev.get("sentences", []), list) else []

            # Evidence: list of matched sentences only (capped by executor)
            if ev_sents:
                li = "".join(f"<li>{_escape_html(s)}</li>" for s in ev_sents)
                evidence_html = f"<ul style='margin:8px 0 0 18px;'>{li}</ul>"
            else:
                evidence_html = "<div style='color:#666;margin-top:8px;'>No evidence captured.</div>"

            rules_rows += f"""
              <tr>
                <td style="width:220px;">{_escape_html(rid)}</td>
                <td style="width:160px;">{_escape_html(st)}</td>
                <td style="width:220px;">{_escape_html(cit)}</td>
                <td>
                  <details>
                    <summary>Show evidence</summary>
                    {evidence_html}
                  </details>
                </td>
              </tr>
            """

        sections_html += f"""
          <details>
            <summary><strong>{_escape_html(sec_title)}</strong></summary>
            <table border="1" cellpadding="6" style="width:100%; border-collapse:collapse; margin-top:10px;">
              <tr><th>Rule</th><th>Status</th><th>Citation</th><th>Evidence</th></tr>
              {rules_rows}
            </table>
          </details>
        """

    return f"""
    <html>
      <head>
        <title>Results</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body {{ font-family: Arial, sans-serif; margin: 24px; max-width: 1100px; }}
          details {{ margin: 10px 0; }}
          summary {{ cursor: pointer; }}
        </style>
      </head>
      <body>
        <h1>Results</h1>
        <div><strong>Ruleset:</strong> {_escape_html(ruleset_id)} v{_escape_html(ruleset_ver)}</div>
        <div><strong>Checked at:</strong> {_escape_html(checked_at)}</div>
        <pre>{_escape_html(str(summary))}</pre>

        {sections_html}

        <p><a href="/admin/test">Run again</a></p>
      </body>
    </html>
    """


def _escape_html(s: str) -> str:
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


@app.get("/health")
def health():
    return {"status": "ok", "executor_version": EXECUTOR_VERSION}

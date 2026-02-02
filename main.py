from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from typing import Dict, Optional
from executor import run_rules_engine

# --------------------------------------------------
# APP SETUP
# --------------------------------------------------

app = FastAPI(title="Assure Deterministic Compliance Engine")

# --------------------------------------------------
# REQUEST MODEL
# --------------------------------------------------

class CheckRequest(BaseModel):
    advice_type: str
    document_text: str
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False

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
        rules_path="rules/cobs-suitability-v1.yaml"
    )

    return JSONResponse(result)

# --------------------------------------------------
# ADMIN UI (REAL USER FLOW)
# --------------------------------------------------

@app.get("/admin/test", response_class=HTMLResponse)
def admin_test():
    return """
    <html>
    <head>
      <style>
        body { font-family: Arial; max-width: 1100px; margin: 24px; }
        textarea { width: 100%; }
        details { margin-bottom: 16px; border: 1px solid #ddd; padding: 12px; border-radius: 6px; }
        summary { cursor: pointer; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; }
        th, td { border: 1px solid #ccc; padding: 6px; text-align: left; }
        th { background: #f4f4f4; }
        .OK { color: green; font-weight: bold; }
        .POTENTIAL_ISSUE { color: #b26a00; font-weight: bold; }
        .NOT_ASSESSED { color: #666; font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>Assure – Admin Test</h1>

      <form method="post">
        <label>Advice type</label><br/>
        <select name="advice_type">
          <option value="advised">advised</option>
          <option value="standard">standard</option>
        </select><br/><br/>

        <label>Suitability report</label><br/>
        <textarea name="document_text" rows="18"></textarea><br/><br/>

        <button type="submit">Run check</button>
      </form>
    </body>
    </html>
    """

@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_run(
    advice_type: str = Form(...),
    document_text: str = Form(...)
):
    context = {
        "advice_type": advice_type,
        "investment_element": True,
        "ongoing_service": False,
    }

    result = run_rules_engine(
        document_text=document_text,
        context=context,
        rules_path="rules/cobs-suitability-v1.yaml"
    )

    sections_html = ""

    for section_id, rules in result.get("sections", {}).items():
        rows = ""
        for r in rules:
            rows += f"""
            <tr>
              <td>{r["rule_id"]}</td>
              <td class="{r["status"]}">{r["status"]}</td>
              <td>{r["citation"]}</td>
            </tr>
            """

        sections_html += f"""
        <details>
          <summary>{section_id}</summary>
          <table>
            <tr>
              <th>Rule</th>
              <th>Status</th>
              <th>Citation</th>
            </tr>
            {rows}
          </table>
        </details>
        """

    return f"""
    <html>
    <body style="font-family:Arial;max-width:1100px;margin:24px">
      <h1>Results</h1>

      <p>
        <strong>Ruleset:</strong> {result.get("ruleset_id")} v{result.get("ruleset_version")}<br/>
        <strong>Checked at:</strong> {result.get("checked_at")}
      </p>

      <pre>{result.get("summary")}</pre>

      {sections_html}

      <p><a href="/admin/test">Run again</a></p>
    </body>
    </html>
    """

# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}
    

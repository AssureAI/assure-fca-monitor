from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from typing import Dict, Optional, List
from executor import run_rules_engine

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
        rules_path="rules/cobs-suitability-v1.yaml",
    )

    return JSONResponse(result)


# --------------------------------------------------
# ADMIN UI
# --------------------------------------------------

def group_results(results: List[Dict]) -> Dict[str, List[Dict]]:
    grouped: Dict[str, List[Dict]] = {}

    for r in results:
        rule_id = r.get("rule_id", "")
        section = rule_id.split("_")[0]  # COBS9, COBS6, COBS4, STRUCT

        grouped.setdefault(section, []).append(r)

    return grouped


@app.get("/admin/test", response_class=HTMLResponse)
def admin_test():
    return """
    <html>
    <body style="font-family:Arial;max-width:1100px;margin:24px">
      <h1>Assure – Admin Test</h1>

      <form method="post">
        <label>Advice type</label><br/>
        <select name="advice_type">
          <option value="advised">advised</option>
          <option value="standard">standard</option>
        </select><br/><br/>

        <label>Suitability report</label><br/>
        <textarea name="document_text" rows="18" style="width:100%"></textarea><br/><br/>

        <button type="submit">Run check</button>
      </form>
    </body>
    </html>
    """


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_run(
    advice_type: str = Form(...),
    document_text: str = Form(...),
):
    context = {
        "advice_type": advice_type,
        "investment_element": True,
        "ongoing_service": False,
    }

    result = run_rules_engine(
        document_text=document_text,
        context=context,
        rules_path="rules/cobs-suitability-v1.yaml",
    )

    grouped = group_results(result["results"])

    sections_html = ""

    for section, rules in grouped.items():
        rows = ""

        for r in rules:
            evidence_html = ""
            evidence = r.get("evidence", {}).get("sentences", [])

            if evidence:
                evidence_html = "<details><summary>Show evidence</summary><ul>"
                for s in evidence:
                    evidence_html += f"<li>{s}</li>"
                evidence_html += "</ul></details>"

            rows += f"""
            <tr>
              <td>{r["rule_id"]}</td>
              <td>{r["status"]}</td>
              <td>{r["citation"]}</td>
            </tr>
            <tr>
              <td colspan="3">{evidence_html}</td>
            </tr>
            """

        sections_html += f"""
        <details open>
          <summary><strong>{section}</strong></summary>
          <table border="1" cellpadding="6" cellspacing="0" width="100%">
            <tr>
              <th>Rule</th>
              <th>Status</th>
              <th>Citation</th>
            </tr>
            {rows}
          </table>
        </details>
        <br/>
        """

    return f"""
    <html>
    <body style="font-family:Arial;max-width:1100px;margin:24px">
      <h1>Results</h1>

      <p>
        <strong>Ruleset:</strong> {result["ruleset_id"]} v{result["ruleset_version"]}<br/>
        <strong>Checked at:</strong> {result["checked_at"]}
      </p>

      <pre>{result["summary"]}</pre>

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

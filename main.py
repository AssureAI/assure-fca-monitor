from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from typing import Dict, Optional
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
    document_text: str = Form(...)
):
    payload = {
        "advice_type": advice_type,
        "document_text": document_text,
        "investment_element": True,
        "ongoing_service": False,
    }

    result = run_rules_engine(
        document_text=document_text,
        context=payload,
        rules_path="rules/cobs-suitability-v1.yaml"
    )

    rows = "".join(
        f"<tr><td>{r['rule_id']}</td><td>{r['status']}</td><td>{r['citation']}</td></tr>"
        for r in result["results"]
    )

    return f"""
    <html>
    <body style="font-family:Arial;max-width:1100px;margin:24px">
      <h1>Results</h1>
      <table border="1" cellpadding="6">
        <tr><th>Rule</th><th>Status</th><th>Citation</th></tr>
        {rows}
      </table>
      <pre>{result}</pre>
      <p><a href="/admin/test">Run again</a></p>
    </body>
    </html>
    """


@app.get("/health")
def health():
    return {"status": "ok"}

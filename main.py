from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Dict
from executor import run_rules_engine

app = FastAPI(title="Assure Compliance Engine")


@app.post("/check")
async def check(payload: Dict):
    return run_rules_engine(
        document_text=payload["document_text"],
        context=payload,
        rules_path="rules/cobs-suitability-v1.yaml",
    )


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
        </select><br/><br/>

        <textarea name="document_text" rows="16" style="width:100%"></textarea><br/>
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
        rules_path="rules/cobs-suitability-v1.yaml",
    )

    sections_html = ""

    for section, rules in result["sections"].items():
        rules_html = ""
        for r in rules:
            ev = "".join(f"<li>{e}</li>" for e in r["evidence"])
            rules_html += f"""
            <details>
              <summary><strong>{r['title']}</strong> – {r['status']}</summary>
              <ul>{ev}</ul>
            </details>
            """
        sections_html += f"<h3>{section}</h3>{rules_html}"

    return f"""
    <html>
    <body style="font-family:Arial;max-width:1100px;margin:24px">
      <h1>Results</h1>
      <pre>{result["summary"]}</pre>
      {sections_html}
      <p><a href="/admin/test">Run again</a></p>
    </body>
    </html>
    """


@app.get("/health")
def health():
    return {"status": "ok"}

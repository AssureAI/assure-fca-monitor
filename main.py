from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse
from executor import run_rules_engine
from collections import defaultdict

app = FastAPI(title="Assure Deterministic Compliance Engine")

# -----------------------------
# API
# -----------------------------

@app.post("/check")
async def check(payload: dict):
    return JSONResponse(
        run_rules_engine(
            document_text=payload["document_text"],
            context=payload,
            rules_path="rules/cobs-suitability-v1.yaml"
        )
    )


# -----------------------------
# ADMIN UI
# -----------------------------

@app.get("/admin/test", response_class=HTMLResponse)
def admin_test():
    return """
    <html><body style="font-family:Arial;max-width:1200px;margin:24px">
    <h1>Assure – Admin Test</h1>
    <form method="post">
      <textarea name="document_text" rows="20" style="width:100%"></textarea><br/><br/>
      <button type="submit">Run check</button>
    </form>
    </body></html>
    """


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_run(document_text: str = Form(...)):
    result = run_rules_engine(
        document_text=document_text,
        context={"advice_type": "advised", "investment_element": True},
        rules_path="rules/cobs-suitability-v1.yaml"
    )

    grouped = defaultdict(list)
    for r in result["results"]:
        grouped[r["section"]].append(r)

    html = f"""
    <html><body style="font-family:Arial;max-width:1200px;margin:24px">
    <h1>Results</h1>
    <pre>{result["summary"]}</pre>
    """

    for section, rules in grouped.items():
        html += f"<details open><summary><b>{section}</b></summary><table border=1 width='100%'>"
        html += "<tr><th>Rule</th><th>Status</th><th>Citation</th><th>Evidence</th></tr>"
        for r in rules:
            ev = r.get("evidence", {})
            html += f"""
            <tr>
              <td>{r["rule_id"]}</td>
              <td>{r["status"]}</td>
              <td>{r["citation"]}</td>
              <td>
                <b>✔ Positive</b><ul>{"".join(f"<li>{s}</li>" for s in ev.get("positive", []))}</ul>
                <b>⚠ Negative</b><ul>{"".join(f"<li>{s}</li>" for s in ev.get("negative", []))}</ul>
              </td>
            </tr>
            """
        html += "</table></details><br/>"

    html += "<p><a href='/admin/test'>Run again</a></p></body></html>"
    return html


@app.get("/health")
def health():
    return {"status": "ok"}

from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from typing import Dict, Optional, Any, List, Tuple
import traceback

from executor import run_rules_engine

app = FastAPI(title="Assure Deterministic Compliance Engine")


class CheckRequest(BaseModel):
    advice_type: str
    document_text: str
    investment_element: Optional[bool] = True
    ongoing_service: Optional[bool] = False


@app.post("/check")
async def check(payload: CheckRequest):
    context: Dict[str, Any] = {
        "advice_type": payload.advice_type,
        "investment_element": bool(payload.investment_element),
        "ongoing_service": bool(payload.ongoing_service),
    }

    try:
        result = run_rules_engine(
            document_text=payload.document_text,
            context=context,
            rules_path="rules/cobs-suitability-v1.yaml",
        )
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse(
            {"error": str(e), "traceback": traceback.format_exc()},
            status_code=500,
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
          <option value="standard">standard</option>
        </select><br/><br/>

        <label>Suitability report</label><br/>
        <textarea name="document_text" rows="18" style="width:100%"></textarea><br/><br/>

        <button type="submit">Run check</button>
      </form>
    </body>
    </html>
    """


def _normalise_sections(sections: Any) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """
    Accept:
      - dict: {section_name: [rules...]}
      - list: [{"section": "...", "rules": [...]}, ...]
    Return:
      - list of (section_name, rules_list)
    """
    if isinstance(sections, dict):
        out: List[Tuple[str, List[Dict[str, Any]]]] = []
        for name, rules in sections.items():
            if isinstance(rules, list):
                out.append((str(name), rules))
            else:
                out.append((str(name), []))
        return out

    if isinstance(sections, list):
        out2: List[Tuple[str, List[Dict[str, Any]]]] = []
        for sec in sections:
            if isinstance(sec, dict):
                name = sec.get("section") or sec.get("name") or "Unsorted"
                rules = sec.get("rules") if isinstance(sec.get("rules"), list) else []
                out2.append((str(name), rules))
        return out2

    return []


def _render_results_html(result: Dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    sections_any = result.get("sections") or {}

    ruleset_id = result.get("ruleset_id", "unknown")
    version = result.get("ruleset_version", "unknown")
    checked_at = result.get("checked_at", "")

    sections = _normalise_sections(sections_any)

    accordion_parts = []
    for section_name, rules in sections:
        ok = sum(1 for r in rules if r.get("status") == "OK")
        pi = sum(1 for r in rules if r.get("status") == "POTENTIAL_ISSUE")
        na = sum(1 for r in rules if r.get("status") == "NOT_ASSESSED")

        rows = []
        for r in rules:
            rid = r.get("rule_id", "")
            title = r.get("title", "")
            status = r.get("status", "")
            citation = r.get("citation", "")
            src = r.get("source_url") or ""
            evidence = r.get("evidence") or []

            src_html = f'<div><a href="{src}" target="_blank">{src}</a></div>' if src else ""

            evidence_html = ""
            if isinstance(evidence, list) and evidence:
                lis = "".join(f"<li>{e}</li>" for e in evidence[:8])
                evidence_html = f"""
                  <details>
                    <summary>Show evidence</summary>
                    <ul style="margin-top:8px">{lis}</ul>
                  </details>
                """

            rows.append(f"""
              <tr>
                <td style="vertical-align:top"><b>{rid}</b><div>{title}</div></td>
                <td style="vertical-align:top">{status}</td>
                <td style="vertical-align:top">{citation}{src_html}</td>
                <td style="vertical-align:top">{evidence_html}</td>
              </tr>
            """)

        table = f"""
          <table border="1" cellpadding="6" cellspacing="0" style="width:100%;border-collapse:collapse">
            <tr><th>Rule</th><th>Status</th><th>Citation</th><th>Evidence</th></tr>
            {''.join(rows)}
          </table>
        """

        accordion_parts.append(f"""
          <details>
            <summary style="font-weight:bold">{section_name} (OK:{ok} PI:{pi} NA:{na})</summary>
            <div style="margin-top:12px">{table}</div>
          </details>
        """)

    return f"""
    <html>
    <body style="font-family:Arial;max-width:1100px;margin:24px">
      <h1>Results</h1>
      <div><b>Ruleset:</b> {ruleset_id} v{version}</div>
      <div><b>Checked at:</b> {checked_at}</div>
      <pre>{summary}</pre>
      <div style="margin-top:12px">{''.join(accordion_parts) if accordion_parts else "<i>No sections returned.</i>"}</div>
      <p><a href="/admin/test">Run again</a></p>
      <hr/>
      <details>
        <summary>Raw JSON (debug)</summary>
        <pre>{result}</pre>
      </details>
    </body>
    </html>
    """


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_run(
    advice_type: str = Form(...),
    document_text: str = Form(...)
):
    context: Dict[str, Any] = {
        "advice_type": advice_type,
        "investment_element": True,
        "ongoing_service": False,
    }

    try:
        result = run_rules_engine(
            document_text=document_text,
            context=context,
            rules_path="rules/cobs-suitability-v1.yaml",
        )
        return _render_results_html(result)
    except Exception as e:
        tb = traceback.format_exc()
        return f"""
        <html>
        <body style="font-family:Arial;max-width:1100px;margin:24px">
          <h1>Internal Server Error</h1>
          <p><b>{str(e)}</b></p>
          <pre>{tb}</pre>
          <p><a href="/admin/test">Back</a></p>
        </body>
        </html>
        """


@app.get("/health")
def health():
    return {"status": "ok"}
# main.py
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from executor import run_rules_engine

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/admin/test", response_class=HTMLResponse)
async def admin_test_get(request: Request):
    return templates.TemplateResponse(
        "admin_test.html",
        {
            "request": request,
            "result": None,
            "advice_type": "advised",
            "investment_element": "true",
            "ongoing_service": "false",
            "sr_text": "",
        },
    )


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_run(
    request: Request,
    advice_type: str = Form(default="advised"),
    investment_element: str = Form(default="true"),
    ongoing_service: str = Form(default="false"),
    sr_text: str = Form(default=""),
):
    context = {
        "advice_type": advice_type,
        "investment_element": (investment_element.lower() == "true"),
        "ongoing_service": (ongoing_service.lower() == "true"),
    }

    result = run_rules_engine(
        document_text=sr_text or "",
        context=context,
        rules_path="rules/cobs-suitability-v1.yaml",
    )

    # Defensive: always ensure these exist so template never KeyErrors
    result.setdefault("summary", {"ok": 0, "potential_issue": 0, "not_assessed": 0})
    result.setdefault("sections", {})

    return templates.TemplateResponse(
        "admin_test.html",
        {
            "request": request,
            "result": result,
            "advice_type": advice_type,
            "investment_element": investment_element,
            "ongoing_service": ongoing_service,
            "sr_text": sr_text,
        },
    )
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.templating import Jinja2Templates

from executor import run_rules_engine

app = FastAPI()

templates = Jinja2Templates(directory="templates")


@app.get("/", include_in_schema=False)
def root():
    # keep render happy + give a useful landing
    return RedirectResponse(url="/admin/test")


@app.get("/admin/test", response_class=HTMLResponse)
async def admin_test_get(request: Request):
    # default form state
    context = {
        "request": request,
        "advice_type": "advised",
        "investment_element": "true",
        "ongoing_service": "false",
        "sr_text": "",
        "result": None,
    }
    return templates.TemplateResponse("admin_test.html", context)


@app.post("/admin/test", response_class=HTMLResponse)
async def admin_test_post(
    request: Request,
    advice_type: str = Form("advised"),
    investment_element: str = Form("true"),
    ongoing_service: str = Form("false"),
    sr_text: str = Form(""),
):
    # normalise form -> engine context
    ctx = {
        "advice_type": advice_type,
        "investment_element": investment_element.lower() == "true",
        "ongoing_service": ongoing_service.lower() == "true",
    }

    result = run_rules_engine(
        document_text=sr_text or "",
        context=ctx,
        rules_path="rules/cobs-suitability-v2.yaml"
    )

    # Re-render SAME page with results (and auto-scroll in template)
    page_ctx = {
        "request": request,
        "advice_type": advice_type,
        "investment_element": investment_element,
        "ongoing_service": ongoing_service,
        "sr_text": sr_text,
        "result": result,
    }
    return templates.TemplateResponse("admin_test.html", page_ctx)
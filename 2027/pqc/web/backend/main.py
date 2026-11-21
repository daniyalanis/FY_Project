from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.keygen import router as keygen_router
from backend.core.config import STATIC_DIR, TEMPLATES_DIR

app = FastAPI(
    title="ML-KEM FIPS 203",
    description="Browser interface for the ML-KEM FIPS 203 standard implementation.",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)
app.include_router(keygen_router)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the single-page interface."""
    return templates.TemplateResponse(request, "index.html")


@app.get("/health")
async def health():
    """Lightweight application health check."""
    return {"status": "ok"}

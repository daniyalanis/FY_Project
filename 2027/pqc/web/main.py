from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from models import (
    DecapsulationRequest,
    DecapsulationResponse,
    EncapsulationRequest,
    EncapsulationResponse,
    KeyGenRequest,
    KeyGenResponse,
)
from operations import RunError, artifact, decap, encap, keygen

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"

app = FastAPI(
    title="ML-KEM FIPS 203",
    description="Browser interface for the ML-KEM FIPS 203 standard implementation.",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=FRONTEND / "static"), name="static")
templates = Jinja2Templates(directory=FRONTEND / "templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/keygen/run", response_model=KeyGenResponse)
async def run_keygen(request: KeyGenRequest):
    try:
        return KeyGenResponse(**await keygen(request))
    except RunError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Key generation failed.") from exc


@app.get("/api/keygen/download/{run_id}/{name}")
async def download_key(run_id: str, name: str):
    if name not in {"ek", "dk"}:
        raise HTTPException(status_code=404, detail="Unknown key artifact.")
    path = artifact(run_id, name)
    if path is None:
        raise HTTPException(status_code=404, detail="Key artifact not found.")
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)


@app.post("/api/operations/encapsulate", response_model=EncapsulationResponse)
async def run_encap(request: EncapsulationRequest):
    try:
        return EncapsulationResponse(**await encap(request))
    except RunError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Encapsulation failed.") from exc


@app.post("/api/operations/decapsulate", response_model=DecapsulationResponse)
async def run_decap(request: DecapsulationRequest):
    try:
        return DecapsulationResponse(**await decap(request))
    except RunError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Decapsulation failed.") from exc


@app.get("/api/operations/download/{run_id}/{name}")
async def download_operation(run_id: str, name: str):
    path = artifact(run_id, name)
    if path is None or name in {"ek", "dk"}:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from backend.schemas.operations import (
    DecapsulationRequest,
    DecapsulationResponse,
    EncapsulationRequest,
    EncapsulationResponse,
)
from backend.services.operations_service import (
    OperationError,
    decapsulate,
    encapsulate,
    get_artifact,
)

router = APIRouter(prefix="/api/operations", tags=["Operations"])


@router.post("/encapsulate", response_model=EncapsulationResponse)
async def run_encapsulation(request: EncapsulationRequest) -> EncapsulationResponse:
    try:
        return EncapsulationResponse(**await encapsulate(request))
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Encapsulation failed.") from exc


@router.post("/decapsulate", response_model=DecapsulationResponse)
async def run_decapsulation(request: DecapsulationRequest) -> DecapsulationResponse:
    try:
        return DecapsulationResponse(**await decapsulate(request))
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Decapsulation failed.") from exc


@router.get("/download/{execution_id}/{artifact_name}")
async def download_artifact(execution_id: str, artifact_name: str):
    path = get_artifact(execution_id, artifact_name)
    if path is None:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)

"""HTTP routes for ML-KEM key generation."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from backend.schemas.keygen import KeyGenRequest, KeyGenResponse
from backend.services.keygen_service import KeyGenError, generate_keypair, get_artifact

router = APIRouter(prefix="/api/keygen", tags=["KeyGen"])


@router.post("/run", response_model=KeyGenResponse)
async def run_keygen(request: KeyGenRequest) -> KeyGenResponse:
    """Generate an ML-KEM key pair and return metadata plus hexadecimal keys."""
    try:
        result = await generate_keypair(request)
        return KeyGenResponse(**result)
    except KeyGenError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        # Do not expose internal exception details or cryptographic material.
        raise HTTPException(status_code=500, detail="Key generation failed.") from exc


@router.get("/download/{execution_id}/{key_name}")
async def download_key(execution_id: str, key_name: str):
    """Download one generated binary key."""
    if key_name not in {"ek", "dk"}:
        raise HTTPException(status_code=404, detail="Unknown key artifact.")

    path = get_artifact(execution_id, key_name)
    if path is None:
        raise HTTPException(status_code=404, detail="Key artifact not found.")

    filename = "ek.bin" if key_name == "ek" else "dk.bin"
    return FileResponse(path, media_type="application/octet-stream", filename=filename)

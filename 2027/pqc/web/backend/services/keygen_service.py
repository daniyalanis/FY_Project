from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any
import sys

from starlette.concurrency import run_in_threadpool

CODE_DIR = Path(__file__).resolve().parents[3] / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from keygen import ML_KEM_KeyGen, PARAMETER_SETS

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "outputs"


class KeyGenError(Exception):
    """Expected input or execution error suitable for an API response."""


def _execute(parameter_set: int, d: bytes | None, z: bytes | None):
    """Execute the original synchronous algorithm outside the event loop."""
    started = time.perf_counter()
    ek, dk = ML_KEM_KeyGen(parameter_set, d, z)
    elapsed = time.perf_counter() - started
    return ek, dk, elapsed


async def generate_keypair(request) -> dict[str, Any]:
    """Invoke KeyGen, persist its outputs, and construct the API result."""
    if request.parameter_set not in PARAMETER_SETS:
        raise KeyGenError("Parameter set must be 512, 768 or 1024.")

    d = bytes.fromhex(request.d_hex) if request.mode == "deterministic" else None
    z = bytes.fromhex(request.z_hex) if request.mode == "deterministic" else None

    try:
        ek, dk, elapsed = await run_in_threadpool(
            _execute, request.parameter_set, d, z
        )
    except Exception as exc:
        raise KeyGenError("The cryptographic key-generation operation failed.") from exc

    execution_id = uuid.uuid4().hex
    run_dir = OUTPUT_DIR / execution_id
    run_dir.mkdir(parents=True, exist_ok=False)

    # Preserve the algorithm's returned byte strings exactly.
    (run_dir / "ek.bin").write_bytes(ek)
    (run_dir / "dk.bin").write_bytes(dk)

    return {
        "execution_id": execution_id,
        "status": "completed",
        "algorithm": "ML-KEM",
        "operation": "KeyGen",
        "parameter_set": request.parameter_set,
        "mode": request.mode,
        "execution_time_seconds": round(elapsed, 8),
        "outputs": {
            "ek": {
                "filename": "ek.bin",
                "size_bytes": len(ek),
                "download_url": f"/api/keygen/download/{execution_id}/ek",
            },
            "dk": {
                "filename": "dk.bin",
                "size_bytes": len(dk),
                "download_url": f"/api/keygen/download/{execution_id}/dk",
            },
        },
        # Hex is returned for inspection in this demonstration UI.
        "ek_hex": ek.hex(),
        "dk_hex": dk.hex(),
    }


def get_artifact(execution_id: str, key_name: str) -> Path | None:
    """Resolve an artifact only within its generated execution directory."""
    if not execution_id.isalnum() or len(execution_id) != 32:
        return None
    path = OUTPUT_DIR / execution_id / f"{key_name}.bin"
    return path if path.is_file() else None

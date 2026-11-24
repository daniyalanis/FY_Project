from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from typing import Any

from starlette.concurrency import run_in_threadpool

CODE_DIR = Path(__file__).resolve().parents[3] / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from decap import ML_KEM_Decaps
from encap import ML_KEM_Encaps
from keygen import PARAMETER_SETS

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "outputs"


class OperationError(Exception):
    pass


def _decode(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex("".join(value.split()))
    except ValueError as exc:
        raise OperationError(f"{label} must be hexadecimal.") from exc


def _run_encapsulation(ek: bytes, parameter_set: int):
    started = time.perf_counter()
    shared_secret, ciphertext = ML_KEM_Encaps(ek, parameter_set)
    return shared_secret, ciphertext, time.perf_counter() - started


def _run_decapsulation(dk: bytes, ciphertext: bytes, parameter_set: int):
    started = time.perf_counter()
    shared_secret = ML_KEM_Decaps(dk, ciphertext, parameter_set)
    return shared_secret, time.perf_counter() - started


def _artifact(run_dir: Path, execution_id: str, name: str, data: bytes) -> dict[str, Any]:
    filename = f"{name}.bin"
    (run_dir / filename).write_bytes(data)
    return {
        "filename": filename,
        "size_bytes": len(data),
        "download_url": f"/api/operations/download/{execution_id}/{name}",
    }


def _run_dir() -> tuple[str, Path]:
    execution_id = uuid.uuid4().hex
    run_dir = OUTPUT_DIR / execution_id
    run_dir.mkdir(parents=True, exist_ok=False)
    return execution_id, run_dir


async def encapsulate(request) -> dict[str, Any]:
    if request.parameter_set not in PARAMETER_SETS:
        raise OperationError("Parameter set must be 512, 768 or 1024.")

    ek = _decode(request.ek_hex, "Encapsulation key")
    try:
        shared_secret, ciphertext, elapsed = await run_in_threadpool(
            _run_encapsulation, ek, request.parameter_set
        )
    except Exception as exc:
        raise OperationError(str(exc)) from exc

    execution_id, run_dir = _run_dir()
    return {
        "execution_id": execution_id,
        "status": "completed",
        "operation": "Encapsulation",
        "parameter_set": request.parameter_set,
        "execution_time_seconds": round(elapsed, 8),
        "outputs": {
            "ct": _artifact(run_dir, execution_id, "ct", ciphertext),
            "shared_secret": _artifact(run_dir, execution_id, "K_encap", shared_secret),
        },
        "ct_hex": ciphertext.hex(),
        "shared_secret_hex": shared_secret.hex(),
    }


async def decapsulate(request) -> dict[str, Any]:
    if request.parameter_set not in PARAMETER_SETS:
        raise OperationError("Parameter set must be 512, 768 or 1024.")

    dk = _decode(request.dk_hex, "Decapsulation key")
    ciphertext = _decode(request.ct_hex, "Ciphertext")
    try:
        shared_secret, elapsed = await run_in_threadpool(
            _run_decapsulation, dk, ciphertext, request.parameter_set
        )
    except Exception as exc:
        raise OperationError(str(exc)) from exc

    expected = None
    if request.expected_shared_secret_hex:
        expected = _decode(request.expected_shared_secret_hex, "Encapsulation shared secret")

    execution_id, run_dir = _run_dir()
    return {
        "execution_id": execution_id,
        "status": "completed",
        "operation": "Decapsulation",
        "parameter_set": request.parameter_set,
        "execution_time_seconds": round(elapsed, 8),
        "outputs": {
            "shared_secret": _artifact(run_dir, execution_id, "K_decap", shared_secret),
        },
        "shared_secret_hex": shared_secret.hex(),
        "matches_encapsulation": None if expected is None else shared_secret == expected,
    }


def get_artifact(execution_id: str, artifact_name: str) -> Path | None:
    if not execution_id.isalnum() or len(execution_id) != 32:
        return None
    if artifact_name not in {"ct", "K_encap", "K_decap"}:
        return None
    path = OUTPUT_DIR / execution_id / f"{artifact_name}.bin"
    return path if path.is_file() else None

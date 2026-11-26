from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from typing import Any

from starlette.concurrency import run_in_threadpool

ROOT = Path(__file__).resolve().parent
CODE = ROOT.parent / "code"
OUT = ROOT / "outputs"
if str(CODE) not in sys.path:
    sys.path.insert(0, str(CODE))

from decap import ML_KEM_Decaps
from encap import ML_KEM_Encaps
from keygen import ML_KEM_KeyGen, PARAMETER_SETS


class RunError(Exception):
    pass


def _hex(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex("".join(value.split()))
    except ValueError as exc:
        raise RunError(f"{label} must be hexadecimal.") from exc


def _dir() -> tuple[str, Path]:
    run_id = uuid.uuid4().hex
    path = OUT / run_id
    path.mkdir(parents=True, exist_ok=False)
    return run_id, path


def _save(path: Path, run_id: str, name: str, data: bytes) -> dict[str, Any]:
    filename = f"{name}.bin"
    (path / filename).write_bytes(data)
    return {
        "filename": filename,
        "size_bytes": len(data),
        "download_url": f"/api/operations/download/{run_id}/{name}",
    }


def _keys(parameter_set: int, d: bytes | None, z: bytes | None):
    started = time.perf_counter()
    ek, dk = ML_KEM_KeyGen(parameter_set, d, z)
    return ek, dk, time.perf_counter() - started


async def keygen(request) -> dict[str, Any]:
    if request.parameter_set not in PARAMETER_SETS:
        raise RunError("Parameter set must be 512, 768 or 1024.")
    d = _hex(request.d_hex, "D") if request.mode == "deterministic" else None
    z = _hex(request.z_hex, "Z") if request.mode == "deterministic" else None
    try:
        ek, dk, elapsed = await run_in_threadpool(_keys, request.parameter_set, d, z)
    except Exception as exc:
        raise RunError("The cryptographic key-generation operation failed.") from exc

    run_id, path = _dir()
    (path / "ek.bin").write_bytes(ek)
    (path / "dk.bin").write_bytes(dk)
    return {
        "execution_id": run_id,
        "status": "completed",
        "algorithm": "ML-KEM",
        "operation": "KeyGen",
        "parameter_set": request.parameter_set,
        "mode": request.mode,
        "execution_time_seconds": round(elapsed, 8),
        "outputs": {
            "ek": {"filename": "ek.bin", "size_bytes": len(ek), "download_url": f"/api/keygen/download/{run_id}/ek"},
            "dk": {"filename": "dk.bin", "size_bytes": len(dk), "download_url": f"/api/keygen/download/{run_id}/dk"},
        },
        "ek_hex": ek.hex(),
        "dk_hex": dk.hex(),
    }


async def encap(request) -> dict[str, Any]:
    if request.parameter_set not in PARAMETER_SETS:
        raise RunError("Parameter set must be 512, 768 or 1024.")
    ek = _hex(request.ek_hex, "Encapsulation key")
    try:
        started = time.perf_counter()
        key, ct = await run_in_threadpool(ML_KEM_Encaps, ek, request.parameter_set)
        elapsed = time.perf_counter() - started
    except Exception as exc:
        raise RunError(str(exc)) from exc

    run_id, path = _dir()
    return {
        "execution_id": run_id,
        "status": "completed",
        "operation": "Encapsulation",
        "parameter_set": request.parameter_set,
        "execution_time_seconds": round(elapsed, 8),
        "outputs": {
            "ct": _save(path, run_id, "ct", ct),
            "shared_secret": _save(path, run_id, "K_encap", key),
        },
        "ct_hex": ct.hex(),
        "shared_secret_hex": key.hex(),
    }


async def decap(request) -> dict[str, Any]:
    if request.parameter_set not in PARAMETER_SETS:
        raise RunError("Parameter set must be 512, 768 or 1024.")
    dk = _hex(request.dk_hex, "Decapsulation key")
    ct = _hex(request.ct_hex, "Ciphertext")
    try:
        started = time.perf_counter()
        key = await run_in_threadpool(ML_KEM_Decaps, dk, ct, request.parameter_set)
        elapsed = time.perf_counter() - started
    except Exception as exc:
        raise RunError(str(exc)) from exc

    expected = _hex(request.expected_shared_secret_hex, "Encapsulation shared secret") if request.expected_shared_secret_hex else None
    run_id, path = _dir()
    return {
        "execution_id": run_id,
        "status": "completed",
        "operation": "Decapsulation",
        "parameter_set": request.parameter_set,
        "execution_time_seconds": round(elapsed, 8),
        "outputs": {"shared_secret": _save(path, run_id, "K_decap", key)},
        "shared_secret_hex": key.hex(),
        "matches_encapsulation": None if expected is None else key == expected,
    }


def artifact(run_id: str, name: str) -> Path | None:
    if not run_id.isalnum() or len(run_id) != 32 or name not in {"ek", "dk", "ct", "K_encap", "K_decap"}:
        return None
    path = OUT / run_id / f"{name}.bin"
    return path if path.is_file() else None

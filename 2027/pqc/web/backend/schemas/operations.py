from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel


class Artifact(BaseModel):
    filename: str
    size_bytes: int
    download_url: str


class EncapsulationRequest(BaseModel):
    parameter_set: Literal[512, 768, 1024]
    ek_hex: str


class EncapsulationResponse(BaseModel):
    execution_id: str
    status: str
    operation: str
    parameter_set: int
    execution_time_seconds: float
    outputs: dict[str, Artifact]
    ct_hex: str
    shared_secret_hex: str


class DecapsulationRequest(BaseModel):
    parameter_set: Literal[512, 768, 1024]
    dk_hex: str
    ct_hex: str
    expected_shared_secret_hex: Optional[str] = None


class DecapsulationResponse(BaseModel):
    execution_id: str
    status: str
    operation: str
    parameter_set: int
    execution_time_seconds: float
    outputs: dict[str, Artifact]
    shared_secret_hex: str
    matches_encapsulation: Optional[bool] = None

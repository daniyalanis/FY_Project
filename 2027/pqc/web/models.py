from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


class Artifact(BaseModel):
    filename: str
    size_bytes: int
    download_url: str


class KeyGenRequest(BaseModel):
    parameter_set: Literal[512, 768, 1024] = 512
    mode: Literal["random", "deterministic"] = "random"
    d_hex: Optional[str] = Field(default=None)
    z_hex: Optional[str] = Field(default=None)

    @model_validator(mode="after")
    def check_seeds(self):
        if self.mode == "deterministic":
            if not self.d_hex or not self.z_hex:
                raise ValueError("Deterministic mode requires both D and Z seeds.")
            for label, value in (("D", self.d_hex), ("Z", self.z_hex)):
                if len(value) != 64:
                    raise ValueError(f"{label} must contain exactly 64 hexadecimal characters (32 bytes).")
                try:
                    bytes.fromhex(value)
                except ValueError as exc:
                    raise ValueError(f"{label} must be valid hexadecimal.") from exc
        elif self.d_hex is not None or self.z_hex is not None:
            raise ValueError("Seeds may only be supplied in deterministic mode.")
        return self


class KeyGenResponse(BaseModel):
    execution_id: str
    status: str
    algorithm: str
    operation: str
    parameter_set: int
    mode: str
    execution_time_seconds: float
    outputs: dict[str, Artifact]
    ek_hex: str
    dk_hex: str


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

"""Validated request and response models for ML-KEM KeyGen."""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field, model_validator


class KeyGenRequest(BaseModel):
    parameter_set: Literal[512, 768, 1024] = 512
    mode: Literal["random", "deterministic"] = "random"
    d_hex: Optional[str] = Field(default=None, description="32-byte seed encoded as 64 hexadecimal characters.")
    z_hex: Optional[str] = Field(default=None, description="32-byte seed encoded as 64 hexadecimal characters.")

    @model_validator(mode="after")
    def validate_seed_mode(self):
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


class KeyArtifact(BaseModel):
    filename: str
    size_bytes: int
    download_url: str


class KeyGenResponse(BaseModel):
    execution_id: str
    status: str
    algorithm: str
    operation: str
    parameter_set: int
    mode: str
    execution_time_seconds: float
    outputs: dict[str, KeyArtifact]
    ek_hex: str
    dk_hex: str

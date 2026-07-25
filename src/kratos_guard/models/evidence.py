"""Atomic evidence records."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Observation(StrictModel):
    subject: str
    claim: str
    value: str
    source: str
    observed_at: datetime


class Uncertainty(StrictModel):
    subject: str
    state: str
    reason: str
    next_proof: str


class CommandEvidence(StrictModel):
    argv: list[str]
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    read_only: bool = True


class HashEvidence(StrictModel):
    path: str
    algorithm: str = "sha256"
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    byte_count: int = Field(ge=0)

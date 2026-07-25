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
    command_id: str
    started_at: datetime
    finished_at: datetime
    duration_ms: float = Field(ge=0)
    executable: str
    sanitised_arguments: list[str]
    working_directory: str
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_excerpt: str
    stderr_excerpt: str
    mutation_classification: str
    policy_decision: str
    timed_out: bool = False


class HashEvidence(StrictModel):
    path: str
    algorithm: str = "sha256"
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    byte_count: int = Field(ge=0)

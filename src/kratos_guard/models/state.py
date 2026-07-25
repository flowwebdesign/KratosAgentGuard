"""Shared evidence states."""

from enum import StrEnum


class EvidenceState(StrEnum):
    PROVEN = "PROVEN"
    CONTRADICTED = "CONTRADICTED"
    UNPROVEN = "UNPROVEN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSPECTION_FAILED = "INSPECTION_FAILED"

"""Canonical JSON evidence."""

import json
from pathlib import Path

from pydantic import BaseModel

from kratos_guard.models import InspectionReport
from kratos_guard.reporting.redaction import redact


def render_json(report: BaseModel) -> str:
    payload = redact(report.model_dump(mode="json"))
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_json(report: InspectionReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(report), encoding="utf-8")

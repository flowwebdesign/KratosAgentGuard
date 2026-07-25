"""Project profile contract."""

from pathlib import Path
from typing import Any

import yaml


def load_profile(profile: str) -> dict[str, Any]:
    path = Path(__file__).parent / profile / "profile.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"unknown profile: {profile}")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"profile must contain a mapping: {path}")
    return loaded

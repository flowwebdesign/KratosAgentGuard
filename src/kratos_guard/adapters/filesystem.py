"""Bounded filesystem observations."""

from pathlib import Path


def describe_path(path: Path) -> dict[str, object]:
    resolved = path.resolve()
    if not resolved.exists():
        return {"path": str(resolved), "exists": False, "kind": "missing", "entries": []}
    kind = "directory" if resolved.is_dir() else "file"
    entries = (
        [child.name for child in sorted(resolved.iterdir())[:100]] if resolved.is_dir() else []
    )
    return {"path": str(resolved), "exists": True, "kind": kind, "entries": entries}

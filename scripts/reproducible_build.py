"""Build the wheel and source archive twice and require byte-identical output."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_once(repository: Path, destination: Path, environment: dict[str, str]) -> None:
    subprocess.run(
        ["uv", "build", "--out-dir", str(destination)],
        check=True,
        cwd=repository,
        env=environment,
        timeout=180,
    )


def artifact_hashes(directory: Path) -> dict[str, str]:
    artifacts = sorted(
        path
        for path in directory.iterdir()
        if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    if len(artifacts) != 2:
        raise RuntimeError(f"expected one wheel and one source archive, found {len(artifacts)}")
    return {path.name: file_sha256(path) for path in artifacts}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", type=Path)
    options = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    output = (options.output_directory or repository / "dist").resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = repository / ".work"
    work.mkdir(exist_ok=True)
    environment = dict(os.environ)
    if "SOURCE_DATE_EPOCH" not in environment:
        completed = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            capture_output=True,
            check=True,
            cwd=repository,
            text=True,
            timeout=30,
        )
        environment["SOURCE_DATE_EPOCH"] = completed.stdout.strip()

    with tempfile.TemporaryDirectory(prefix="reproducible-build-", dir=work) as temporary:
        root = Path(temporary)
        first = root / "first"
        second = root / "second"
        first.mkdir()
        second.mkdir()
        build_once(repository, first, environment)
        build_once(repository, second, environment)
        first_hashes = artifact_hashes(first)
        second_hashes = artifact_hashes(second)
        if first_hashes != second_hashes:
            raise RuntimeError(
                "REPRODUCIBLE_BUILD_MISMATCH:"
                + json.dumps(
                    {"first": first_hashes, "second": second_hashes},
                    sort_keys=True,
                )
            )
        for name in sorted(first_hashes):
            shutil.copyfile(first / name, output / name)

    print(
        json.dumps(
            {
                "artifacts": first_hashes,
                "source_date_epoch": environment["SOURCE_DATE_EPOCH"],
                "verdict": "PASS_REPRODUCIBLE_BUILD",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

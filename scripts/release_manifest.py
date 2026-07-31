"""Create deterministic release checksums and an SPDX 2.3 dependency SBOM."""

import argparse
import json
import os
import tomllib
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-directory", type=Path)
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    dist = (options.dist_directory or root / "dist").resolve()
    lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    source_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    created = (
        datetime.fromtimestamp(int(source_epoch), tz=UTC)
        if source_epoch
        else datetime.now(UTC)
    )
    packages = []
    for package in sorted(lock.get("package", []), key=lambda item: item["name"]):
        name = str(package["name"])
        version = str(package.get("version", "1.0.0" if name == "kratos-agent-guard" else ""))
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{name.replace('_', '-').replace('.', '-')}",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
            }
        )
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "kratos-agent-guard-1.0.0",
        "documentNamespace": (
            "https://github.com/flowwebdesign/KratosAgentGuard/"
            f"spdx/{os.environ.get('GITHUB_SHA', 'local')}"
        ),
        "creationInfo": {
            "created": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: KratosAgentGuard-release-manifest-1.0.0"],
        },
        "packages": packages,
    }
    sbom_path = dist / "kratos-agent-guard-1.0.0.spdx.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    subjects = sorted(
        path
        for path in dist.iterdir()
        if path.is_file()
        and (
            path.suffix == ".whl"
            or path.name.endswith(".tar.gz")
            or path.name.endswith(".spdx.json")
        )
    )
    checksums = "".join(f"{file_sha256(path)}  {path.name}\n" for path in subjects)
    (dist / "SHA256SUMS").write_text(checksums, encoding="utf-8", newline="\n")
    print(
        json.dumps(
            {
                "artifact_count": len(subjects),
                "sbom_package_count": len(packages),
                "verdict": "PASS_RELEASE_MANIFEST_CREATED",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

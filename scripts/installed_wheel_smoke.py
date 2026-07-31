"""Install the built wheel and prove the v1 standalone lifecycle outside the checkout."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Any


def run_json(
    python: Path,
    arguments: list[str],
    *,
    environment: dict[str, str],
    working_directory: Path,
    expected: tuple[int, ...] = (0,),
) -> dict[str, Any]:
    completed = subprocess.run(
        [str(python), "-m", "kratos_guard", *arguments],
        capture_output=True,
        check=False,
        cwd=working_directory,
        env=environment,
        text=True,
        timeout=60,
    )
    if completed.returncode not in expected:
        raise RuntimeError(
            f"installed command failed ({completed.returncode}): {arguments}\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("installed command returned non-object JSON")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-directory", type=Path)
    options = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    dist = (options.dist_directory or repository / "dist").resolve()
    wheels = sorted(dist.glob("kratos_agent_guard-1.0.0-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one v1 wheel, found {len(wheels)}")
    work = repository / ".work"
    work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="installed-wheel-", dir=work) as temporary:
        root = Path(temporary)
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        if sys.platform == "win32":
            environment["LOCALAPPDATA"] = str(root / "local-app-data")
        else:
            environment["XDG_DATA_HOME"] = str(root / "xdg-data")
        environment_root = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment_root)
        python = (
            environment_root / "Scripts" / "python.exe"
            if sys.platform == "win32"
            else environment_root / "bin" / "python"
        )
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--force-reinstall",
                str(wheels[0]),
            ],
            check=True,
            cwd=root,
            env=environment,
            timeout=120,
        )
        fixture = root / "fixture"
        fixture.mkdir()
        (fixture / "worker.js").write_text("installed v1 fixture\n", encoding="utf-8")

        initialised = run_json(
            python, ["standalone", "init"], environment=environment, working_directory=root
        )
        service_template = root / "kratos-agent-guard.service"
        run_json(
            python,
            [
                "standalone",
                "service-template",
                "--kind",
                "systemd",
                "--output",
                str(service_template),
            ],
            environment=environment,
            working_directory=root,
        )
        if "ProtectSystem=strict" not in service_template.read_text(encoding="utf-8"):
            raise RuntimeError("installed service template is missing hardening policy")
        added = run_json(
            python,
            ["standalone", "folder", "add", "--path", str(fixture), "--label", "fixture"],
            environment=environment,
            working_directory=root,
        )
        run_json(
            python,
            ["standalone", "run", "--iterations", "1"],
            environment=environment,
            working_directory=root,
        )
        old_key = initialised["key_id"]
        rotated = run_json(
            python,
            ["key", "rotate", "--reason", "installed-wheel-smoke"],
            environment=environment,
            working_directory=root,
        )
        if rotated["new_key_id"] == old_key:
            raise RuntimeError("installed key rotation did not change identity")
        run_json(
            python,
            ["standalone", "run", "--iterations", "1"],
            environment=environment,
            working_directory=root,
        )
        status = run_json(
            python,
            ["standalone", "status"],
            environment=environment,
            working_directory=root,
        )
        health = run_json(
            python,
            ["standalone", "health"],
            environment=environment,
            working_directory=root,
        )
        run_json(
            python,
            ["standalone", "evidence", "checkpoint"],
            environment=environment,
            working_directory=root,
        )
        evidence_root = Path(initialised["configuration"]["evidence_root"])
        bundle = evidence_root / "exports" / "installed-wheel.zip"
        run_json(
            python,
            ["standalone", "evidence", "export", "--destination", str(bundle)],
            environment=environment,
            working_directory=root,
        )
        verification = run_json(
            python,
            [
                "standalone",
                "evidence",
                "verify",
                "--bundle",
                str(bundle),
                "--expected-trust-anchor-key-id",
                old_key,
            ],
            environment=environment,
            working_directory=root,
        )
        imported = run_json(
            python,
            [
                "standalone",
                "evidence",
                "import",
                "--bundle",
                str(bundle),
                "--expected-trust-anchor-key-id",
                old_key,
            ],
            environment=environment,
            working_directory=root,
        )
        run_json(
            python,
            [
                "standalone",
                "folder",
                "remove",
                "--folder-id",
                str(added["folder_id"]),
            ],
            environment=environment,
            working_directory=root,
        )
        if status["verdict"] != "PASS_STANDALONE_V1_READY":
            raise RuntimeError(f"installed status blocked: {status['blockers']}")
        if not health["verdict"].startswith("PASS_"):
            raise RuntimeError(f"installed health blocked: {health['blockers']}")
        if verification["verdict"] != "PASS_EVIDENCE_BUNDLE_VERIFIED":
            raise RuntimeError(f"installed bundle failed: {verification['blockers']}")
        print(
            json.dumps(
                {
                    "bundle_verdict": verification["verdict"],
                    "ledger_entry_count": verification["ledger_entry_count"],
                    "new_key_id": rotated["new_key_id"],
                    "import_verdict": imported["verdict"],
                    "status_verdict": status["verdict"],
                    "verdict": "PASS_INSTALLED_WHEEL_SMOKE",
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

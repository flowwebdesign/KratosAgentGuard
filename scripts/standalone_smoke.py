"""Exercise the standalone CLI without inspecting or mutating an external target."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run_guard(
    arguments: list[str],
    *,
    environment: dict[str, str],
    expected_exit_codes: tuple[int, ...] = (0,),
) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-m", "kratos_guard", *arguments],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=60,
    )
    if completed.returncode not in expected_exit_codes:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"command did not return JSON: {' '.join(arguments)}\n{completed.stdout}"
        ) from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"command returned a non-object: {' '.join(arguments)}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-clean-status",
        action="store_true",
        help="require the final standalone status to pass; intended for clean CI checkouts",
    )
    options = parser.parse_args()
    guard_root = Path(__file__).resolve().parents[1]
    work_root = guard_root / ".work"
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="standalone-smoke-", dir=work_root) as temporary:
        root = Path(temporary)
        environment = dict(os.environ)
        if sys.platform == "win32":
            environment["LOCALAPPDATA"] = str(root / "local-app-data")
        else:
            environment["XDG_DATA_HOME"] = str(root / "xdg-data")

        fixture = root / "fixture"
        evidence = root / "evidence"
        trust_directory = root / "trust"
        fixture.mkdir()
        evidence.mkdir()
        (fixture / "worker.js").write_text("standalone smoke fixture\n", encoding="utf-8")
        challenge_path = evidence / "challenge.json"
        synthetic_directory = evidence / "synthetic"
        replay_directory = evidence / "replay"
        snapshot_path = evidence / "snapshot.json"
        ledger_path = evidence / "ledger.jsonl"

        key = run_guard(["key", "initialise"], environment=environment)
        trust = run_guard(
            [
                "key",
                "export-public",
                "--trust-directory",
                str(trust_directory),
            ],
            environment=environment,
        )
        trust_key = str(trust["trusted_public_key_path"])
        challenge = run_guard(
            [
                "attestation",
                "issue",
                "--subject",
                "guard-owned-standalone-smoke",
                "--output",
                str(challenge_path),
            ],
            environment=environment,
        )
        synthetic = run_guard(
            [
                "attestation",
                "synthetic-produce",
                "--challenge-path",
                str(challenge_path),
                "--artifact-root",
                str(fixture),
                "--output-directory",
                str(synthetic_directory),
            ],
            environment=environment,
        )
        verification_arguments = [
            "attestation",
            "verify",
            "--challenge-path",
            str(challenge_path),
            "--statement-path",
            str(synthetic["statement_path"]),
            "--guard-trust-key",
            trust_key,
            "--producer-trust-key",
            str(synthetic["producer_trust_path"]),
            "--replay-directory",
            str(replay_directory),
        ]
        verification = run_guard(verification_arguments, environment=environment)
        replay = run_guard(
            verification_arguments,
            environment=environment,
            expected_exit_codes=(3,),
        )
        snapshot = run_guard(
            [
                "monitor",
                "snapshot",
                "--root",
                str(fixture),
                "--output",
                str(snapshot_path),
            ],
            environment=environment,
        )
        run_guard(
            [
                "ledger",
                "append",
                "--event-type",
                "guard.smoke.completed",
                "--subject",
                "standalone",
                "--payload-json",
                json.dumps({"challenge_id": challenge["challenge_id"]}),
                "--ledger",
                str(ledger_path),
            ],
            environment=environment,
        )
        ledger = run_guard(
            [
                "ledger",
                "verify",
                "--trust-key",
                trust_key,
                "--ledger",
                str(ledger_path),
            ],
            environment=environment,
        )
        status = run_guard(
            [
                "standalone-status",
                "--ledger",
                str(ledger_path),
                "--trust-key",
                trust_key,
                "--configured-folder",
                str(fixture),
            ],
            environment=environment,
            expected_exit_codes=(0, 3),
        )

        if verification["verdict"] != "PASS_SYNTHETIC_RUNTIME_ATTESTATION":
            raise RuntimeError("synthetic attestation did not pass")
        if replay["blockers"] != ["ATTESTATION_REPLAY_DETECTED"]:
            raise RuntimeError("challenge replay was not rejected exactly once")
        if ledger["verdict"] != "PASS_LEDGER_VERIFIED":
            raise RuntimeError("ledger did not verify")
        if status["evidence_ledger_state"] != "PASS_LEDGER_VERIFIED":
            raise RuntimeError("status did not cryptographically verify the ledger")
        if options.require_clean_status and status["verdict"] != "PASS_STANDALONE_GUARD_READY":
            raise RuntimeError(f"clean CI status did not pass: {status['blockers']}")
        if status["verdict"] != "PASS_STANDALONE_GUARD_READY" and status["blockers"] != [
            "GUARD_REPOSITORY_DIRTY"
        ]:
            raise RuntimeError(f"unexpected standalone status blockers: {status['blockers']}")

        print(
            json.dumps(
                {
                    "challenge_id": challenge["challenge_id"],
                    "fixture_manifest_sha256": snapshot["manifest_sha256"],
                    "key_id": key["key_id"],
                    "ledger_head_hash": ledger["head_hash"],
                    "replay_verdict": replay["verdict"],
                    "standalone_status_verdict": status["verdict"],
                    "verdict": "PASS_STANDALONE_CLI_SMOKE",
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

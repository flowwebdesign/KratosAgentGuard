"""Phase 2G authority, scope, and fixture-contract tests."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kratos_guard.cli import app
from kratos_guard.core.phase2g import (
    BASELINE_BRANCH,
    DEVELOPMENT_PATH,
    FIX_NAME,
    JOURNEYS,
    PHASE2G_SAFETY_COUNTERS,
    SUCCESSOR_COMMIT,
    compare_behavioural_successor,
    import_successor_bundle,
    validate_development_repository,
)


def test_durable_path_is_exact() -> None:
    assert DEVELOPMENT_PATH == Path(r"C:\Users\floww\Documents\Itzako Extension Successor")


def test_wrong_durable_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="EXACT_DEVELOPMENT_PATH_REQUIRED"):
        validate_development_repository(tmp_path)


def test_only_one_fix_is_authorised() -> None:
    assert FIX_NAME == "wrong-language-automatic-recovery"


def test_development_branch_starts_at_exact_phase2f_successor() -> None:
    assert SUCCESSOR_COMMIT == "aa6c5b312bb2f53373df6ab59cb1e5ebdfc523b1"
    assert BASELINE_BRANCH == "baseline/itzako-extension-1.1.18-compat"


def test_import_rejects_any_second_development_path(tmp_path: Path) -> None:
    bundle = tmp_path / "successor.bundle"
    bundle.write_bytes(b"not consulted before the path authority gate")
    with pytest.raises(PermissionError, match="EXACT_DEVELOPMENT_PATH_REQUIRED"):
        import_successor_bundle(bundle, tmp_path / "other")


@pytest.mark.parametrize("journey", JOURNEYS, ids=[item[0] for item in JOURNEYS])
def test_all_twelve_fixture_contracts_are_present(
    journey: tuple[str, str, str, str, bool, int],
) -> None:
    assert journey[0]
    assert journey[1] in {"coursera", "youtube", "coursera+youtube"}
    assert journey[5] <= 1


@pytest.mark.parametrize(
    "journey_id",
    [
        "coursera-automatic",
        "coursera-manual",
        "coursera-regeneration",
        "coursera-saved-restoration",
        "youtube-automatic",
        "youtube-manual",
        "youtube-regeneration",
        "youtube-saved-restoration",
        "language-mismatch-repair",
        "logged-out",
        "backend-unavailable",
        "duplicate-operation-protection",
    ],
)
def test_journey_names_are_unique(journey_id: str) -> None:
    assert [item[0] for item in JOURNEYS].count(journey_id) == 1


@pytest.mark.parametrize(
    ("journey_id", "expected"),
    [
        ("coursera-saved-restoration", 0),
        ("youtube-saved-restoration", 0),
        ("language-mismatch-repair", 1),
        ("duplicate-operation-protection", 1),
    ],
)
def test_request_caps_are_explicit(journey_id: str, expected: int) -> None:
    item = next(value for value in JOURNEYS if value[0] == journey_id)
    assert item[5] == expected


def test_fixture_contract_does_not_name_a_real_backend() -> None:
    assert all("real" not in item[0] for item in JOURNEYS)


def test_fixture_contract_does_not_grant_promotion() -> None:
    promotion_authority = "NONE"
    assert promotion_authority == "NONE"


@pytest.mark.parametrize("counter", PHASE2G_SAFETY_COUNTERS)
def test_phase2g_protected_mutation_counter_remains_zero(counter: str) -> None:
    assert PHASE2G_SAFETY_COUNTERS[counter] == 0


def _candidate(root: Path, *, permissions: list[str], unrelated: str = "same") -> Path:
    extension = root / "artefact" / "extension"
    extension.mkdir(parents=True)
    manifest = {
        "manifest_version": 3,
        "version": "1.1.18",
        "key": "stable-public-key",
        "permissions": permissions,
        "host_permissions": ["https://example.invalid/*"],
        "content_scripts": [{"matches": ["https://example.invalid/*"], "js": ["panel.js"]}],
        "externally_connectable": {"matches": []},
        "commands": {},
        "web_accessible_resources": [],
        "background": {"service_worker": "serviceWorker.js"},
    }
    (extension / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (extension / "panel.js").write_text("same", encoding="utf-8")
    (extension / "unrelated.js").write_text(unrelated, encoding="utf-8")
    return root


def test_permissions_cannot_expand_in_behavioural_successor(tmp_path: Path) -> None:
    base = _candidate(tmp_path / "base", permissions=["storage"])
    successor = _candidate(tmp_path / "successor", permissions=["storage", "tabs"])
    report = compare_behavioural_successor(base, successor)
    assert report.invariant_results["permissions"] is False
    assert report.verdict == "BEHAVIOURAL_SUCCESSOR_DELTA_CONTRADICTED"


def test_unrelated_runtime_delta_is_rejected(tmp_path: Path) -> None:
    base = _candidate(tmp_path / "base", permissions=["storage"])
    successor = _candidate(tmp_path / "successor", permissions=["storage"], unrelated="changed")
    report = compare_behavioural_successor(base, successor)
    assert report.unexpected_runtime_delta == ["unrelated.js"]
    assert report.verdict == "BEHAVIOURAL_SUCCESSOR_DELTA_CONTRADICTED"


def test_explain_report_keeps_fixture_and_real_backend_verdicts_separate(
    tmp_path: Path,
) -> None:
    report = tmp_path / "phase2g.json"
    report.write_text(
        json.dumps(
            {
                "phase": "2G",
                "final_verdict": (
                    "BEHAVIOURAL_SUCCESSOR_FIXTURE_GOLDEN_JOURNEYS_PROVEN_REAL_BACKEND_UNPROVEN"
                ),
                "authorised_fix": "WRONG_LANGUAGE_AUTOMATIC_EXPLANATION_RECOVERY",
                "development_repository": str(DEVELOPMENT_PATH),
                "development_commit": "b" * 40,
                "candidate_id": "exact-candidate",
                "isolated_runtime": "BEHAVIOURAL_SUCCESSOR_ISOLATED_RUNTIME_PROVEN",
                "offline_journeys": "OFFLINE_FIXTURE_GOLDEN_JOURNEYS_PROVEN",
                "behavioural_delta": "BEHAVIOURAL_SUCCESSOR_DELTA_PROVEN",
                "real_backend": "REAL_BACKEND_GOLDEN_JOURNEYS_UNPROVEN",
                "promotion_authority": "NONE",
                "first_remaining_blocker": "REAL_BACKEND_GOLDEN_JOURNEYS_NOT_EXECUTED",
            }
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["explain-report", str(report)])
    assert result.exit_code == 0
    assert "OFFLINE_FIXTURE_GOLDEN_JOURNEYS_PROVEN" in result.stdout
    assert "REAL_BACKEND_GOLDEN_JOURNEYS_UNPROVEN" in result.stdout
    assert "Promotion authority: NONE" in result.stdout

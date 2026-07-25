from pathlib import Path

from kratos_guard.core.inspection_runner import inspect_target, verifier_identity
from kratos_guard.models import InspectionReport


def test_git_common_directory_recorded_after_initialisation() -> None:
    identity = verifier_identity()
    assert identity.git_common_directory.endswith(".git")


def test_target_inspection_performs_zero_writes(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    before = list(target.iterdir())
    report = inspect_target(target, "itzako")
    assert list(target.iterdir()) == before
    assert report.target_write_count == 0


def test_git_metadata_timestamp_is_not_a_target_product_write(tmp_path: Path) -> None:
    target = tmp_path / "target"
    metadata = target / ".git"
    metadata.mkdir(parents=True)
    (metadata / "probe").write_text("before", encoding="utf-8")
    report = inspect_target(target, "itzako")
    (metadata / "probe").write_text("after", encoding="utf-8")
    assert report.target_write_count == 0


def test_report_schema_round_trips(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    report = inspect_target(target, "itzako")
    restored = InspectionReport.model_validate_json(report.model_dump_json())
    assert restored == report

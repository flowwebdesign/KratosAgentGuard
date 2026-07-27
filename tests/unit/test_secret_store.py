from pathlib import Path

from kratos_guard.core import secret_store


def test_secret_store_round_trip_without_plaintext_on_disk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(secret_store, "secret_store_root", lambda: tmp_path)
    monkeypatch.setattr(
        secret_store,
        "_restrict_directory",
        lambda path: path.mkdir(exist_ok=True),
    )
    monkeypatch.setattr(secret_store, "_protect", lambda value: b"sealed:" + value[::-1])
    monkeypatch.setattr(
        secret_store,
        "_unprotect",
        lambda value: value.removeprefix(b"sealed:")[::-1],
    )

    identity = secret_store.store_secret("phase2i", "audit_token", "secret-value")

    assert secret_store.load_secret("phase2i", "audit_token") == "secret-value"
    assert "secret-value" not in (tmp_path / "phase2i.json").read_text(encoding="utf-8")
    assert identity.name == "audit_token"
    assert len(identity.fingerprint_sha256) == 64


def test_secret_store_rejects_path_like_namespace() -> None:
    try:
        secret_store._namespace_path("../escape")
    except ValueError as exc:
        assert str(exc) == "INVALID_SECRET_NAMESPACE"
    else:
        raise AssertionError("unsafe namespace accepted")

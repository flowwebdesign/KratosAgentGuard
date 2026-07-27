"""Windows DPAPI-backed local secret storage.

The store exposes fingerprints and labels to evidence reports, never plaintext.
Ciphertext is bound to the current Windows user by DPAPI and the containing
directory receives the same restrictive ACL policy as the signing-key store.
"""

from __future__ import annotations

import base64
import ctypes
import getpass
import hashlib
import json
import os
import subprocess
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


@dataclass(frozen=True)
class SecretIdentity:
    namespace: str
    name: str
    fingerprint_sha256: str
    store_path: str
    protection: str = "WINDOWS_DPAPI_CURRENT_USER"


def secret_store_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise RuntimeError("LOCALAPPDATA_REQUIRED_FOR_SECRET_STORE")
    return Path(local) / "KratosAgentGuard" / "secrets"


def _restrict_directory(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)
        return
    completed = subprocess.run(
        [
            "icacls",
            str(root),
            "/inheritance:r",
            "/grant:r",
            f"{getpass.getuser()}:(OI)(CI)F",
            "SYSTEM:(OI)(CI)F",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if completed.returncode:
        raise PermissionError("SECRET_STORE_ACL_RESTRICTION_FAILED")


def _blob(data: bytes) -> tuple[_DataBlob, object]:
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return _DataBlob(len(data), buffer), buffer


def _protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("WINDOWS_DPAPI_REQUIRED")
    source, source_buffer = _blob(data)
    del source_buffer
    target = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        "Kratos Agent Guard local secret",
        None,
        None,
        None,
        0x01,
        ctypes.byref(target),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def _unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("WINDOWS_DPAPI_REQUIRED")
    source, source_buffer = _blob(data)
    del source_buffer
    target = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        0x01,
        ctypes.byref(target),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def _namespace_path(namespace: str) -> Path:
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-_"
    if not namespace or any(character not in allowed for character in namespace):
        raise ValueError("INVALID_SECRET_NAMESPACE")
    return secret_store_root() / f"{namespace}.json"


def store_secret(namespace: str, name: str, value: str) -> SecretIdentity:
    if not name or not value:
        raise ValueError("SECRET_NAME_AND_VALUE_REQUIRED")
    root = secret_store_root()
    _restrict_directory(root)
    path = _namespace_path(namespace)
    payload: dict[str, str] = {}
    if path.is_file():
        decoded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(decoded, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in decoded.items()
        ):
            raise ValueError("SECRET_STORE_FORMAT_INVALID")
        payload = decoded
    payload[name] = base64.b64encode(_protect(value.encode("utf-8"))).decode("ascii")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return SecretIdentity(
        namespace=namespace,
        name=name,
        fingerprint_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        store_path=str(path),
    )


def load_secret(namespace: str, name: str) -> str:
    path = _namespace_path(namespace)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get(name), str):
        raise KeyError("SECRET_NOT_FOUND")
    protected = base64.b64decode(payload[name], validate=True)
    return _unprotect(protected).decode("utf-8")


def inspect_secret(namespace: str, name: str) -> SecretIdentity:
    value = load_secret(namespace, name)
    return SecretIdentity(
        namespace=namespace,
        name=name,
        fingerprint_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        store_path=str(_namespace_path(namespace)),
    )

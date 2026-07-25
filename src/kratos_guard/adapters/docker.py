"""Strict read-only Docker inspection."""

import json
import subprocess

from kratos_guard.models import EvidenceState
from kratos_guard.models.provenance import ContainerIdentity
from kratos_guard.reporting.redaction import redact

ALLOWED = {
    ("version",),
    ("ps",),
    ("inspect",),
    ("container", "inspect"),
    ("image", "inspect"),
}


def assert_docker_read_only(arguments: list[str]) -> None:
    prefix = tuple(arguments[:2]) if tuple(arguments[:2]) in ALLOWED else tuple(arguments[:1])
    if prefix not in ALLOWED:
        raise PermissionError(f"Docker command is not read-only allowlisted: {arguments!r}")


def inspect_containers() -> tuple[list[ContainerIdentity], list[str]]:
    arguments = ["ps", "--format", "{{json .}}"]
    assert_docker_read_only(arguments)
    try:
        completed = subprocess.run(
            ["docker", *arguments],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        return [], [type(error).__name__]
    if completed.returncode != 0:
        return [], ["docker ps unavailable"]
    containers = []
    for line in completed.stdout.splitlines()[:100]:
        item = redact(json.loads(line))
        containers.append(
            ContainerIdentity(
                container_id=str(item.get("ID", "")),
                name=str(item.get("Names", "")),
                image_reference=str(item.get("Image", "")),
                command=str(item.get("Command", "")),
                exposed_ports=[str(item.get("Ports", ""))],
                state=EvidenceState.UNPROVEN,
                uncertainties=[
                    "Image tag and container name do not prove immutable image identity."
                ],
            )
        )
    return containers, []

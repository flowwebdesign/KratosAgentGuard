"""Passive Windows-compatible process inspection."""

from datetime import UTC, datetime
from typing import Any

import psutil

from kratos_guard.models import EvidenceState
from kratos_guard.models.provenance import ListeningEndpoint, RuntimeProcessIdentity
from kratos_guard.reporting.redaction import redact_text


def inspect_listeners(ports: set[int]) -> list[RuntimeProcessIdentity]:
    by_pid: dict[int, list[ListeningEndpoint]] = {}
    for connection in psutil.net_connections(kind="tcp"):
        if connection.status != psutil.CONN_LISTEN or not connection.laddr:
            continue
        port = int(connection.laddr.port)
        if port not in ports or connection.pid is None:
            continue
        endpoint = ListeningEndpoint(
            address=str(connection.laddr.ip),
            port=port,
            pid=connection.pid,
            state=EvidenceState.PROVEN,
        )
        by_pid.setdefault(connection.pid, []).append(endpoint)
    results: list[RuntimeProcessIdentity] = []
    for pid, endpoints in sorted(by_pid.items()):
        errors: list[str] = []
        values: dict[str, Any] = {}
        try:
            process = psutil.Process(pid)
            with process.oneshot():
                values = {
                    "parent_pid": process.ppid(),
                    "executable": process.exe(),
                    "command_line": [redact_text(item) for item in process.cmdline()],
                    "working_directory": process.cwd(),
                    "creation_time": datetime.fromtimestamp(process.create_time(), UTC),
                }
        except (psutil.AccessDenied, psutil.NoSuchProcess) as error:
            errors.append(type(error).__name__)
        results.append(
            RuntimeProcessIdentity(
                pid=pid,
                endpoints=endpoints,
                state=EvidenceState.PROVEN if values else EvidenceState.INSPECTION_FAILED,
                errors=errors,
                **values,
            )
        )
    return results

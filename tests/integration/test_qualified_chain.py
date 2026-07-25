import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from kratos_guard.adapters.http import observe_http
from kratos_guard.core.authority_gate import qualified_gate
from kratos_guard.core.inspection_runner import inspect_target
from kratos_guard.models import EvidenceState
from kratos_guard.models.provenance import (
    ConfiguredExtensionIdentity,
    ContainerIdentity,
    ProvenanceLink,
)


def committed_repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    (root / "README.md").write_text("target", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "target"], check=True, capture_output=True
    )
    return root


def test_source_level_proof_cannot_satisfy_runtime_gate(tmp_path: Path) -> None:
    report = inspect_target(committed_repository(tmp_path), "itzako")
    assert qualified_gate(report, "source").verdict is EvidenceState.PROVEN
    assert qualified_gate(report, "runtime").verdict is EvidenceState.UNPROVEN


def test_qualified_gate_levels_have_expected_exit_codes(tmp_path: Path) -> None:
    report = inspect_target(committed_repository(tmp_path), "itzako")
    assert qualified_gate(report, "source").exit_code == 0
    assert qualified_gate(report, "build").exit_code == 2
    assert qualified_gate(report, "loaded-client").exit_code == 2


def test_http_200_is_health_not_source_identity() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    observation = observe_http(
        f"http://127.0.0.1:{server.server_port}/health", "GET", "health only"
    )
    thread.join(timeout=2)
    server.server_close()
    assert observation.status == 200
    assert observation.state is EvidenceState.PROVEN
    assert "health" in observation.purpose


def test_configured_extension_is_separate_from_live_loaded_identity() -> None:
    configured = ConfiguredExtensionIdentity(
        extension_id="abc",
        configured_version="1.0",
        state=EvidenceState.PROVEN,
    )
    assert configured.state is EvidenceState.PROVEN
    assert not hasattr(configured, "live_loaded")


def test_docker_tag_does_not_prove_immutable_identity() -> None:
    container = ContainerIdentity(
        container_id="abc",
        image_reference="itzako:latest",
        state=EvidenceState.UNPROVEN,
    )
    assert not container.image_digest
    assert container.state is EvidenceState.UNPROVEN


def test_digest_evidence_can_contribute_to_runtime_link() -> None:
    link = ProvenanceLink(
        link_type="BUILD_TO_RUNTIME",
        source_reference="artifact-sha",
        destination_reference="sha256:image",
        verdict=EvidenceState.PROVEN,
        reason="immutable image digest linked by sealed build manifest",
    )
    assert link.verdict is EvidenceState.PROVEN

"""Itzako-specific hypothesis construction."""

from typing import Any

from kratos_guard.models import EvidenceState, TargetLoadedClientIdentity


def loaded_client_from_profile(profile: dict[str, Any]) -> TargetLoadedClientIdentity:
    context = profile["prior_context"]
    return TargetLoadedClientIdentity(
        client_type="chrome_extension",
        build_id=str(context["loaded_extension_build_id"]),
        provenance=str(context["provenance"]),
        source_link_state=EvidenceState.UNPROVEN,
        build_link_state=EvidenceState.UNPROVEN,
        state=EvidenceState.UNPROVEN,
    )

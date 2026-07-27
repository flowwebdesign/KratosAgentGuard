# Deterministic provider scenarios

The audit successor exposes five fake-provider scenarios: `same_language_success`, `wrong_then_correct`, `wrong_then_wrong`, `terminal_timeout`, and `terminal_failure`.

Activation requires audit mode, the exact synthetic claims, database identity, a `KAG-2I-` marker, a matching active lease, and explicit scenario metadata. State is keyed by run marker and operation identity. No normal request can select the seam and no scenario can fall back to an external provider.

Each attempt is recorded in `kag_audit.scenario_events`. Wrong-language repair is capped at two attempts; timeout and failure are deterministic terminal states. This makes browser, backend, queue, and persistence evidence repeatable without claiming real-provider proof.

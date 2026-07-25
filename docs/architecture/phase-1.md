# Phase 1 Architecture

The CLI loads a target profile, invokes bounded read-only adapters, constructs
strict Pydantic evidence models, applies explicit gate semantics, and renders
canonical JSON plus generated Markdown. The verifier identity is collected from
Kratos Agent Guard itself; target identities remain separate.

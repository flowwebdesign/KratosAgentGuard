# Runtime proof scopes

The evidence model separates:

- `SEALED_CANDIDATE_ON_DISK`
- `GUARD_LAUNCHED_BROWSER_PROCESS`
- `ISOLATED_CANARY_LOADED_EXTENSION`
- `CURRENT_USER_LOADED_EXTENSION`
- `PROMOTED_EXTENSION`
- `PRODUCT_BEHAVIOUR`

Each scope has its own evidence state. No state is inherited by another scope without an explicit observed link. In particular, isolated-canary proof cannot satisfy the current-user loaded-client gate.

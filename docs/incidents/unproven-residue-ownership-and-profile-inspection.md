# Unproven residue ownership did not block profile inspection

The residual Chrome-for-Testing profile lacked independent deletion-ownership
proof. Guard therefore preserved it and retained deletion authority `NONE`.
That uncertainty is path-specific: after confirming zero process references,
the residue was excluded from normal Chrome discovery. It neither became
normal-profile evidence nor invalidated privacy-bounded inspection elsewhere.

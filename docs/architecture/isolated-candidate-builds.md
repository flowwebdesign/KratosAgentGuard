# Isolated Candidate Builds

Candidates live under ignored `.work/candidates/<candidate-id>`. Only component
manifest entries enter `source/`. JavaScript syntax validation and deterministic
copying run with the copied snapshot as working directory and a minimal
environment. No dependency installation, lifecycle script, network route or
target-side output is part of this static extension build.

# Runtime Inspection

The runtime adapter uses psutil to map configured listening ports to PIDs,
parent PIDs, executables, redacted command lines, working directories, and
creation times. Docker access is restricted to version, listing, and inspection
commands. No environment variables, signals, restarts, execs, or mutations are
permitted. Port ownership proves a process observation, not build provenance.

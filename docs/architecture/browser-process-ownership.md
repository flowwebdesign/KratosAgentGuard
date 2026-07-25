# Browser process ownership

Guard owns only the subprocess it creates and descendants observed from that root PID. It records the parent, children, executable hash, and actual command line. Shutdown first uses the browser protocol; termination is restricted to the owned tree. Existing normal-browser PIDs are preserved and compared after the run. Uncertain ownership preserves the profile and blocks cleanup.

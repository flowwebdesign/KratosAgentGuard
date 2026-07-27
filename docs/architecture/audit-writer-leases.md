# Audit writer leases

`kag_audit.writer_leases` grants one bounded synthetic writer authority independently of the canonical runtime lease.

A lease binds an ID, run marker, sealed candidate, backend build, audit database, synthetic subject, acquisition/expiry timestamps, status, release time, and terminal outcome. Acquisition rejects an existing active lease or an unexpected scenario-activity baseline. TTL is limited to 600–3600 seconds.

Every audit scenario request must present the matching run and lease metadata. Expired, released, missing, or mismatched leases fail closed. The journey runner releases the lease in both success and exception paths and never modifies canonical writer authority.

# Isolated audit database provisioning

The dedicated PostgreSQL database is `studypilot_kag_audit`. Its `public` schema applies normal migrations through head 017 and remains structurally separate from canonical `studypilot_dev`.

Audit controls live in the separate `kag_audit` schema: synthetic identities, writer leases, scenario runs, and scenario events. They do not create application migration 018.

`kag_audit_backend` can read and mutate required tables only in the audit database and cannot delete, create roles/databases, replicate, or connect to another application database. `kag_audit_readonly` has read-only defaults and no mutation privileges. Independent readback additionally starts a read-only transaction and reports zero write queries.

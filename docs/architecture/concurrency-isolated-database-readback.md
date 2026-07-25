# Concurrency-isolated database readback

Guard forces every database inspection transaction read-only and records the database, schema, migration head, table contract, and credential-redaction state.

Evidence queries are scoped by synthetic owner, marker, operation ID, and creation window. Global counts are context only and cannot attribute unrelated learner activity.

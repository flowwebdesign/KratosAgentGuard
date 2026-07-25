# Language-validation state machine

Automatic flow advances through detecting, generating, validating, and at most one repairing transition. Matching output completes; repeated mismatch, timeout, transport failure, or detector failure reaches explicit retryable failure. Restore never repairs.

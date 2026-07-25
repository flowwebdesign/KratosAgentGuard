# Lesson 45: Semantic oracles versus status-code success

## Established concept

Semantic correctness must be tested independently of transport and operation status.
## Plain-language explanation

A completed request can still contain the wrong answer.
## Why AI agents struggle

HTTP 200 and `ready` are easy assertions; output meaning requires another oracle.
## Itzako example

A ready German explanation cannot satisfy a requested English explanation.
## Guard implementation

The existing deterministic detector compares requested and detected language before display.
## Trade-offs

Detectors have bounded language coverage but avoid paid validation calls.
## Failure modes

Trusting response labels, checking only text presence, or silently accepting `unknown`.
## Practical exercise

Feed same, mismatched, mixed, and undetermined text into the oracle.
## Transfer

Use semantic oracles for currency, locale, schema, and safety classifications.
## Key takeaway

Status proves completion, not correctness.

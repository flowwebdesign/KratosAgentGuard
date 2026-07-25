# Incident: Wrong-language automatic explanation silent failure

## Summary
Automatic generation could reach a ready result whose semantic language did not match the requested output language. Rendering correctly rejected it, but the learner did not receive one bounded automatic recovery attempt and an explicit terminal category.

## Impact
Generation had started, yet the visible outcome could resemble a silent non-start. Repeating generation manually risked unclear request and identity semantics.

## Root boundary
Language detection and render rejection already existed. The missing contract connected mismatch validation to the existing regeneration transition with an operation-scoped cap.

## Correction
Phase 2G adds visible validation and repair states, permits one automatic repair, preserves lesson and operation bindings, excludes saved restoration, and exposes retryable failure after exhaustion.

## Proof scope
Unit/state tests, isolated sealed runtime, and twelve offline fixture journeys are proven. Real backend, provider, normal-profile, and promotion proof remain unexecuted.

# Lesson 56: Synthetic identities as capability boundaries

## Established concept

A synthetic identity should be a narrowly scoped capability, not a disguised normal user.

## Plain-language explanation

Its subject, tenant, audience, scope, database, expiry, and permitted side effects define exactly what it can do.

## Why AI agents struggle

Agents may treat any valid token as sufficient and overlook audience confusion, notification paths, or production membership.

## Itzako example

The Phase 2I token is limited to subject `kag-phase2i`, tenant `kag-audit`, audience `itzako-kag-audit`, and scope `audit:golden-journeys`.

## Guard implementation

Guard stores the token with Windows DPAPI, reports only its fingerprint, and proves no email, billing, invitation, normal-user, or production association.

## Trade-offs

Tight scopes require dedicated authentication plumbing and periodic expiry management.

## Failure modes

Accepting a normal token, logging a secret, omitting audience validation, or letting the identity reach canonical data.

## Practical exercise

Write a capability matrix for one synthetic token and add a negative test for every denied boundary.

## Transfer to another project

Apply this model to test service accounts, CI deploy tokens, and robot users.

## Key takeaway

Identity is safest when its valid uses are explicit and mechanically narrow.

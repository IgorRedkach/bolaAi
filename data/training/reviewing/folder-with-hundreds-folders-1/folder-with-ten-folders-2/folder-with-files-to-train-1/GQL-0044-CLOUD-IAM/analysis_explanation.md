# Analysis Explanation

**System analysed:** VaultGuard IAM API — GQL-0044 (Cloud IAM / Identity Provider)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 10.5 (Draft/non-published resource access). The resolver allows access to resources regardless of status (draft, published, etc.) and regardless of tenant ownership.
2. **Read Section 3.0 schema** — `updateResource(id: ID!, input: ResourceInput!)` confirmed. `ResourceInput` accepts `status` and `ownerId` (confirmed by HAR).
3. **Read Section 4.0** — RISK-GQL-044: resolver does not verify `tenantId`. `bulkResourceLookup` has no per-ID filter.
4. **Read Section 2.0** — Redis cache keyed by `resourceId` only.
5. **Read HAR** — Attack is `updateResource(id: "R-2044", input: {status: "approved", ownerId: "attacker-8cc1f371"})` from `tenant-8cc1` against `tenant-f371`. Response `200 OK` returned `tenant-f371` data: `CONFIDENTIAL-8cc1f371`. `x-request-id: req-8cc1f371`.
6. **Pattern 10.5 in IAM context** — Draft IAM record `R-2044` is escalated to `approved` state by a cross-tenant caller. This is a particularly severe instance of Pattern 10.5: in IAM systems, `approved` state triggers activation of identity/policy bindings. The attacker effectively activates a cross-tenant IAM policy.
7. **State transition authorization** — Added as a separate remediation item: `status: "approved"` requires a dedicated authorization check (role: `approver`) beyond the basic tenant check.

## Consistency Guard
- All tenant IDs (`tenant-8cc1`, `tenant-f371`), resource IDs (`R-2044`), injected ownerId (`attacker-8cc1f371`), leaked values (`CONFIDENTIAL-8cc1f371`, `other-user-8cc1f371`), request IDs (`req-8cc1f371`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.

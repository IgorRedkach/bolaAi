# Analysis Explanation

**System analysed:** WageFlow Payroll API — GQL-0046 (HR / Payroll Processing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 1.2 (Related or linked resources BOLA). The resolver handles linked resources without re-validating ownership when the resource is accessed through a related link.
2. **Read Section 3.0 schema** — `getResource(id: ID!)`, `getResourceWithChildren(id: ID!)` returning `Resource` with `items: [Item!]`. The `getResourceWithChildren` is the linked resource traversal vector.
3. **Read Section 4.0** — RISK-GQL-046: resolver does not verify `tenantId`. `bulkResourceLookup` has no per-ID filter.
4. **Read HAR** — `getResource(id: "R-2046")` from `tenant-666f`. Response `200 OK`: `tenantId: "tenant-fc59"`, `sensitiveField: "CONFIDENTIAL-666ffc59"`, `internalNotes: "Internal data exposed"`. `x-request-id: req-666ffc59`.
5. **Pattern 1.2 application** — The primary attack is direct ID substitution via `getResource`. The "related/linked" pattern escalation is the `getResourceWithChildren` traversal (Step 3), grounded in §3.0 schema's `items: [Item!]` and the missing per-level authorization noted in §5.0.
6. **HR domain impact** — `sensitiveField` in payroll context = salary, compensation, tax data. GDPR/privacy implications noted in report.

## Consistency Guard
- All tenant IDs (`tenant-666f`, `tenant-fc59`), resource IDs (`R-2046`), ownerId (`other-user-666ffc59`), leaked values (`CONFIDENTIAL-666ffc59`), request IDs (`req-666ffc59`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.

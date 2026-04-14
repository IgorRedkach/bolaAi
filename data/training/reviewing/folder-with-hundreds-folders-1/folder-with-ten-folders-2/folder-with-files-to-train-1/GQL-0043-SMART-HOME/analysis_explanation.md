# Analysis Explanation

**System analysed:** NeoBuild BAS Platform — GQL-0043 (Smart Home / Building Automation)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 10.2 (Parameter escalation / own session scope extension). A single user extends their authenticated session scope by substituting parameter values — no extra accounts or privileges needed.
2. **Read Section 3.0 schema** — `updateResource(id: ID!, input: ResourceInput!)` confirmed. The `ResourceInput` accepts `ownerId` as a writable field (confirmed by HAR).
3. **Read Section 4.0** — RISK-GQL-043: resolver does not cross-check `tenantId`. `bulkResourceLookup` has no per-ID filter.
4. **Read Section 2.0** — Redis cache keyed by `resourceId` only, no user/tenant dimension.
5. **Read HAR** — Attack is a WRITE mutation: `updateResource(id: "R-2043", input: {status: "approved", ownerId: "attacker-2ba6094f"})`. Attacker `tenant-2ba6` targeted `tenant-094f`. Response `200 OK` returned `tenant-094f` data. `timings.wait: 50 ms` — consistent with Redis cache hit (no full DB query). `x-request-id: req-2ba6094f`.
6. **Pattern 10.2 interpretation** — "Own session scope extension" = the three escalated parameters (`id`, `status`, `ownerId`) all go beyond the authenticated user's authorized scope. A single JWT suffices — no account compromise.
7. **BAS/smart home impact** — Writing `status: "approved"` to a building automation record has physical-world safety implications (HVAC, access control, fire suppression).

## Consistency Guard
- All tenant IDs (`tenant-2ba6`, `tenant-094f`), resource IDs (`R-2043`), injected ownerId (`attacker-2ba6094f`), leaked values (`CONFIDENTIAL-2ba6094f`, `other-user-2ba6094f`), timing (`50 ms wait`), request IDs (`req-2ba6094f`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.

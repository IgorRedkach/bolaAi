# Analysis Explanation

**System analysed:** PipelinePro Sales API — GQL-0034 (B2B SaaS / CRM)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 3.1 (client-assumed authority). "The client supplies price, role, or status fields that the resolver applies without server-side re-validation."
2. **Read Section 3.0 schema** — `updateProject(id: ID!, input: ProjectInput!)` and `bulkProjectLookup(ids: [ID!]!)` confirmed. `ProjectData` includes `sensitiveField` and `internalNotes`.
3. **Read Section 4.0** — RISK-GQL-034: resolver does not cross-check `tenantId`. Also confirmed `bulkProjectLookup` has no per-ID ownership filtering.
4. **Read HAR** — Attacker (`tenant-e2b2`) sent `bulkProjectLookup(ids: ["P-2034", "P-1034", "P-3034"])`. Response `tenantId: "tenant-47ff"`, `sensitiveField: "CONFIDENTIAL-e2b247ff"`, `internalNotes: "Internal data exposed"`, `x-request-id: req-e2b247ff`. This is the primary HAR evidence.
5. **Pattern 3.1 interpretation** — §5.0 describes status/role/price field escalation without server-side re-validation. Added as Finding 2 with `status: "approved"` as the representative demonstration (directly from schema's `status: String!` field).
6. **Removed speculative steps** — No introspection probe basis; no "if Pattern X" conditionals. Only §4.0 + HAR grounded evidence used.
7. **Redis cache risk** — §2.0 caches by `projectId` only; added remediation for `projectId:tenantId` composite key.

## Consistency Guard
- All tenant IDs (`tenant-e2b2`, `tenant-47ff`), project IDs (`P-2034`, `P-1034`, `P-3034`), leaked values (`CONFIDENTIAL-e2b247ff`, `other-user-e2b247ff`), and request IDs (`req-e2b247ff`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.

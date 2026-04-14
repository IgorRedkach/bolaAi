# Analysis Explanation

**System analysed:** AeroOps Flight Management — GQL-0037 (Aviation / Flight Ops)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 5.1 (Authorization-bypass injection). The `resourceId` resolver does not enforce ownership/tenancy, enabling injection of authorization-bypass through the mutation input.
2. **Read Section 3.0 schema** — `updateResource(id: ID!, input: ResourceInput!)` — `ResourceInput` is not defined inline in the schema excerpt, but the HAR shows it accepts `status` and `ownerId` as writable fields.
3. **Read Section 4.0** — RISK-GQL-037: resolver does not cross-check `tenantId`. `bulkResourceLookup` has no per-ID filter.
4. **Read HAR** — Key finding: the attack is a WRITE mutation, not a read. `updateResource(id: "R-2037", input: {status: "approved", ownerId: "attacker-fa1a33b6"})` from `tenant-fa1a` targeting `tenant-33b6`. Response `200 OK` with cross-tenant data confirms success. `x-request-id: req-fa1a33b6`.
5. **Pattern 5.1 interpretation** — "Authorization-bypass injection" = the attacker injects `ownerId: "attacker-fa1a33b6"` into the mutation input, bypassing the server-side authorization boundary through mass assignment. The `id: "R-2037"` is the cross-tenant BOLA component.
6. **Aviation impact** — Setting `status: "approved"` on a flight management record has direct safety implications; emphasised in report summary.
7. **Removed speculative steps** — Introspection probe has no context basis. Bulk enumeration added from §4.0 explicit note.

## Consistency Guard
- All tenant IDs (`tenant-fa1a`, `tenant-33b6`), resource IDs (`R-2037`), injected ownerId (`attacker-fa1a33b6`), and request IDs (`req-fa1a33b6`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.

# Analysis Explanation

**Folder:** GQL-0250-PARKING
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Architecture Review (§2.0)
ParkIQ Management API (v2.1.3) exposes a single GraphQL endpoint at `https://api.parkiq-management-ap.example.com/graphql` (Apollo Server). Redis caching is keyed solely by `nodeId` — no tenant or user dimension. This means an attacker who knows or enumerates a victim's `nodeId` can poison the cache with cross-tenant data or bypass tenant isolation via cached responses.

### 2. Schema Inspection (§3.0)
`getIntersection(id: ID!)` accepts a plain caller-supplied `id`. The schema places no tenant filter on this argument; resolution is expected to be enforced at the resolver layer (§1.0), but §4.0 confirms it is not. Separately, `bulkIntersectionLookup(ids: [ID!]!)` accepts an arbitrary array of IDs with no per-ID ownership filtering — this is the batch path that Pattern 1.9 directly targets.

### 3. Risk Assessment (§4.0)
RISK-GQL-250 is explicitly documented in context.txt: "The `getIntersection` resolver fetches by `nodeId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`."

### 4. Vulnerability Pattern (§5.0)
Pattern 1.9 — Batch/bulk lookup: The lack of per-ID ownership checks means an attacker can submit a list of IDs spanning multiple tenants in a single `bulkIntersectionLookup` call and receive all results. The HAR trace (§6.0) demonstrates the same root-cause flaw on the `getIntersection` single-record resolver, which shares the same missing tenancy check. Both code paths are vulnerable for the same reason.

### 5. HAR Trace Analysis
- **Request (§6.0):** `POST https://api.parkiq-management-ap.example.com/graphql`, headers: `:authority: api.parkiq-management-ap.example.com`, `authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`, `x-tenant-id: tenant-e6a0`, `content-type: application/json`
- **Request body:** `getIntersection(id: "I-2250")` — attacker supplies node ID for a record owned by `tenant-3106`
- **`x-request-id: req-e6a03106`** is a **response header** in §6.0 (response.headers), NOT a request header. It is NOT included in the reproduction curl command.
- **Response:** `tenantId: tenant-3106`, `ownerId: other-user-e6a03106`, `sensitiveField: CONFIDENTIAL-e6a03106`, `internalNotes: Internal data exposed`

### 6. Reproduction Construction
The curl command in `expected_response.md` uses only the request headers and body from §6.0 of this context.txt: host `api.parkiq-management-ap.example.com`, JWT, `x-tenant-id: tenant-e6a0`, GraphQL query with `id: "I-2250"`. The `x-request-id` is deliberately omitted because it is a server-assigned response header.

### 7. Remediation Justification
- Resolver tenant validation closes the root-cause gap for both `getIntersection` and any bulk-variant.
- Redis cache key extended to `intersection:{tenantId}:{nodeId}` to prevent cross-tenant cache reads.
- `bulkIntersectionLookup` batch filtering is added because Pattern 1.9 specifically targets batch endpoints.
- `internalNotes` field restriction follows the principle of least privilege — the schema exposes it without access control.

---

**Consistency Guard:** All details (system name `ParkIQ Management API`, version `2.1.3`, host `api.parkiq-management-ap.example.com`, node ID `I-2250`, tenants `tenant-e6a0` / `tenant-3106`, JWT, `ownerId: other-user-e6a03106`, `CONFIDENTIAL-e6a03106`, RISK-GQL-250, Pattern 1.9) are sourced exclusively from this folder's context.txt.

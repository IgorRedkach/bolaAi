# Expected Response

## System
- **Domain:** Nuclear / Critical Safety Infrastructure
- **System:** ReactorCore Safety API
- **Example ID:** GQL-0190

## Priority Findings

### Finding 1: Nuclear Safety — Integrity Failure via Persistence Poisoning in bulkResourceLookup Exposes Cross-Tenant Safety Data (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity / Persistence Poisoning via Lifecycle Actions

**Summary:**
Per §4.0 (RISK-GQL-190): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions): lifecycle actions (e.g., bulk lookup with state changes) can poison persisted safety data across tenant boundaries when resource IDs from other tenants are processed. An attacker from `tenant-34a7` queried `bulkResourceLookup(ids: ["R-2190", "R-1190", "R-3190"])` and received safety data belonging to `tenant-e42f`, including `CONFIDENTIAL-34a7e42f`. In Nuclear / Critical Safety Infrastructure, any unauthorized access to or modification of reactor safety records, maintenance logs, or alarm states represents an existential safety and regulatory risk.

**Evidence from HAR:**
- Request: `POST https://api.reactorcore-safety-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-34a7`
- Query: `bulkResourceLookup(ids: ["R-2190", "R-1190", "R-3190"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-e42f"`, `ownerId: "other-user-34a7e42f"`, `sensitiveField: "CONFIDENTIAL-34a7e42f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-34a7e42f`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-190 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 4.2 | Persistence poisoning via lifecycle/bulk actions |
| HAR query | ids array | R-2190 cross-tenant nuclear safety lookup |
| HAR response | tenantId | tenant-e42f returned to tenant-34a7 |
| HAR response | sensitiveField | CONFIDENTIAL-34a7e42f |
| HAR header | x-request-id | req-34a7e42f |

## Steps to Reproduce

### Step 1 — bulkResourceLookup persistence poisoning nuclear safety (HAR)
```bash
curl -s -X POST https://api.reactorcore-safety-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-34a7" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2190\", \"R-1190\", \"R-3190\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-e42f` nuclear safety record including `CONFIDENTIAL-34a7e42f`. **Secure:** FORBIDDEN — only `tenant-34a7` safety records returned.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Lifecycle/bulk actions must validate tenant ownership before any state read or write.
3. Immutable audit log required for all safety record access.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

# Expected Response

## System
- Domain: Aerospace / MRO
- System: WingTech Maintenance Portal
- Example ID: GQL-0126

## Priority Findings

### Finding 1: Aerospace MRO — Graph Traversal Injection via Bulk Resource Lookup (Pattern 5.2)
**Severity:** Critical
**Category:** Injection / Resolver / Graph Traversal Injection

**Summary:**
Per §5.0 (Pattern 5.2 — resolver/graph traversal injection): The `bulkResourceLookup` resolver traverses the graph without enforcing tenancy at each node. An attacker from `tenant-8416` queried `bulkResourceLookup(ids: ["R-2126", "R-1126", "R-3126"])` and received maintenance record data belonging to `tenant-01a9`, including `CONFIDENTIAL-841601a9`. In Aerospace / MRO, unauthorized access to maintenance records risks safety directive violations, airworthiness data exposure, and regulatory non-compliance (FAA/EASA).

**Evidence from HAR:**
- Request: `POST https://api.wingtech-maintenance.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-8416`
- Query: `bulkResourceLookup(ids: ["R-2126", "R-1126", "R-3126"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-01a9"`, `ownerId: "other-user-841601a9"`, `sensitiveField: "CONFIDENTIAL-841601a9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-841601a9`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 5.2 | Resolver/graph traversal injection |
| HAR request | ids array | R-2126, R-1126, R-3126 (cross-tenant) |
| HAR response | tenantId | tenant-01a9 returned for tenant-8416 caller |
| HAR response | sensitiveField | CONFIDENTIAL-841601a9 |

## Steps to Reproduce

### Step 1 — Bulk traversal injection (HAR)
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8416" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2126\", \"R-1126\", \"R-3126\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-01a9` MRO records returned. **Secure:** Only `tenant-8416` records or FORBIDDEN.

## Remediation
1. Enforce tenancy at every graph traversal node: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Limit bulk array size to prevent enumeration.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

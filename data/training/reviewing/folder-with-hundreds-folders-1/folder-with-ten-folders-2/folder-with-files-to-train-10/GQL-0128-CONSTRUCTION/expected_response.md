# Expected Response

## System
- Domain: Construction / BIM Platform
- System: BuildCore BIM Collaboration
- Example ID: GQL-0128

## Priority Findings

### Finding 1: Construction BIM — Operational PII Leakage via Bulk Resource Lookup (Pattern 7.1)
**Severity:** Critical
**Category:** Logging Failures / Operational PII Leakage

**Summary:**
Per §5.0 (Pattern 7.1 — operational PII/PHI leakage): The `bulkResourceLookup` resolver does not enforce ownership or tenancy boundaries, leaking operational BIM data to unauthorized tenants. An attacker from `tenant-2822` queried `bulkResourceLookup(ids: ["R-2128", "R-1128", "R-3128"])` and received BIM collaboration data belonging to `tenant-3c67`, including `CONFIDENTIAL-28223c67`. In Construction / BIM, this exposes architect drawings, structural specifications, subcontractor details, and project financials.

**Evidence from HAR:**
- Request: `POST https://api.buildcore-bim-collab.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-2822`
- Query: `bulkResourceLookup(ids: ["R-2128", "R-1128", "R-3128"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-3c67"`, `ownerId: "other-user-28223c67"`, `sensitiveField: "CONFIDENTIAL-28223c67"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-28223c67`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 7.1 | Operational PII leakage, no tenancy |
| HAR request | ids array | R-2128, R-1128, R-3128 (cross-tenant) |
| HAR response | tenantId | tenant-3c67 returned for tenant-2822 caller |
| HAR response | sensitiveField | CONFIDENTIAL-28223c67 |

## Steps to Reproduce

### Step 1 — Bulk BIM lookup (HAR)
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2822" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2128\", \"R-1128\", \"R-3128\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-3c67` BIM data returned. **Secure:** Only `tenant-2822` data or FORBIDDEN.

## Remediation
1. Bulk lookup server filter: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Mask `internalNotes`; apply field-level access control on BIM data.
3. Audit log all bulk accesses with `x-request-id`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

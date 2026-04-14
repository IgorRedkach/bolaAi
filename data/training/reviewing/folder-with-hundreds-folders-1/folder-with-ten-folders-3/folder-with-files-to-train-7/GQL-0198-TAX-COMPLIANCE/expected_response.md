# Expected Response

## System
- **Domain:** Tax Compliance / Financial Reporting
- **System:** TaxGrid Compliance API
- **Example ID:** GQL-0198

## Priority Findings

### Finding 1: Tax Compliance — Draft Resource Access via listResources Exposes Cross-Tenant Tax Filing Data (Pattern 10.5)
**Severity:** High
**Category:** Single-User / Draft / Non-Published Resource Access

**Summary:**
Per §4.0 (RISK-GQL-198): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 10.5 — draft/non-published resource access): the `listResources` endpoint returns draft tax filings belonging to other tenants when a caller-supplied `tenantId` is accepted without JWT validation. An attacker from `tenant-ab08` queried `listResources(tenantId: "tenant-0889")` and received draft tax filing records belonging to `tenant-0889`, including `CONFIDENTIAL-ab080889`. In Tax Compliance / Financial Reporting, unauthorized access to draft tax returns, financial statements, and compliance records violates tax secrecy laws and financial regulations.

**Evidence from HAR:**
- Request: `POST https://api.taxgrid-compliance-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-ab08`
- Query: `listResources(tenantId: "tenant-0889") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-0889"`, `ownerId: "other-user-ab080889"`, `sensitiveField: "CONFIDENTIAL-ab080889"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-ab080889`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-198 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 10.5 | Draft resource returned to unauthorized tenant |
| HAR query | tenantId: "tenant-0889" | Caller-injected cross-tenant draft tax filter |
| HAR response | tenantId | tenant-0889 returned to tenant-ab08 |
| HAR response | sensitiveField | CONFIDENTIAL-ab080889 |
| HAR header | x-request-id | req-ab080889 |

## Steps to Reproduce

### Step 1 — listResources draft tax filing cross-tenant access (HAR)
```bash
curl -s -X POST https://api.taxgrid-compliance-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ab08" \
  -d '{"query": "query { listResources(tenantId: \"tenant-0889\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-0889` draft tax records including `CONFIDENTIAL-ab080889`. **Secure:** FORBIDDEN — `tenantId` from JWT; draft resources filtered to `tenant-ab08` only.

## Remediation
1. Ignore caller-supplied `tenantId`; enforce `WHERE tenant_id = $jwt.tenantId AND status != 'draft' OR user_is_owner` in resolver.
2. Draft resources must only be accessible by their owning tenant.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

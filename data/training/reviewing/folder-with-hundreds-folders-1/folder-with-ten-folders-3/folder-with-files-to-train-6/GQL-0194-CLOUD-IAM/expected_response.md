# Expected Response

## System
- **Domain:** Cloud IAM / Identity & Access Management
- **System:** VaultGuard IAM API
- **Example ID:** GQL-0194

## Priority Findings

### Finding 1: Cloud IAM — Operational PII Leakage via bulkResourceLookup Exposes Cross-Tenant Identity Records (Pattern 7.1)
**Severity:** High
**Category:** Logging Failures / Operational PII/PHI Leakage

**Summary:**
Per §4.0 (RISK-GQL-194): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 7.1 — operational PII/PHI leakage): sensitive identity data returned in API responses is not filtered by tenant ownership before logging or returning, causing cross-tenant PII leakage through operational paths. An attacker from `tenant-1db2` queried `bulkResourceLookup(ids: ["R-2194", "R-1194", "R-3194"])` and received identity records belonging to `tenant-387b`, including `CONFIDENTIAL-1db2387b`. In Cloud IAM, exposure of identity records, role assignments, and access policies across tenants enables privilege escalation and lateral movement.

**Evidence from HAR:**
- Request: `POST https://api.vaultguard-iam-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-1db2`
- Query: `bulkResourceLookup(ids: ["R-2194", "R-1194", "R-3194"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-387b"`, `ownerId: "other-user-1db2387b"`, `sensitiveField: "CONFIDENTIAL-1db2387b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-1db2387b`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-194 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 7.1 | Operational PII leakage via bulk response |
| HAR query | ids array | R-2194 cross-tenant IAM record lookup |
| HAR response | tenantId | tenant-387b returned to tenant-1db2 |
| HAR response | sensitiveField | CONFIDENTIAL-1db2387b |
| HAR header | x-request-id | req-1db2387b |

## Steps to Reproduce

### Step 1 — bulkResourceLookup operational PII leakage IAM (HAR)
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1db2" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2194\", \"R-1194\", \"R-3194\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-387b` IAM identity records including `CONFIDENTIAL-1db2387b`. **Secure:** FORBIDDEN — only `tenant-1db2` records returned.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Ensure PII fields are redacted in operational logs — never log `sensitiveField` values.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

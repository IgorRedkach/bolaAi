# Expected Response

## System
- **Domain:** Defense / Secure Repository
- **System:** Aegis Vault Secure Repository
- **Example ID:** GQL-0206

## Priority Findings

### Finding 1: Defense Vault — BOLA via Batch Lookup getResource Exposes Cross-Tenant Classified Records (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA / Batch/Bulk Lookup Endpoints

**Summary:**
Per §4.0 (RISK-GQL-206): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.9 — batch/bulk lookup endpoints): the batch lookup path returns classified records across tenant boundaries when IDs from other tenants are supplied. An attacker from `tenant-f4be` queried `getResource(id: "R-2206")` and received classified records belonging to `tenant-a4ea`, including `CONFIDENTIAL-f4bea4ea`. In Defense / Secure Repository, unauthorized access to classified documents, intelligence records, and mission-critical data constitutes a national security breach.

**Evidence from HAR:**
- Request: `POST https://api.aegis-vault-secure-r.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-f4be`
- Query: `getResource(id: "R-2206") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-a4ea"`, `ownerId: "other-user-f4bea4ea"`, `sensitiveField: "CONFIDENTIAL-f4bea4ea"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f4bea4ea`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-206 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.9 | Batch/bulk lookup returns cross-tenant classified data |
| HAR query | id: "R-2206" | Cross-tenant defense record batch lookup |
| HAR response | tenantId | tenant-a4ea returned to tenant-f4be |
| HAR response | sensitiveField | CONFIDENTIAL-f4bea4ea |
| HAR header | x-request-id | req-f4bea4ea |

## Steps to Reproduce

### Step 1 — getResource batch lookup cross-tenant defense (HAR)
```bash
curl -s -X POST https://api.aegis-vault-secure-r.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f4be" \
  -d '{"query": "query { getResource(id: \"R-2206\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-a4ea` classified record including `CONFIDENTIAL-f4bea4ea`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Batch lookup must validate per-item `tenantId` against JWT before returning any record.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

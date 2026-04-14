# Expected Response

## System
- Domain: Nuclear / Safety Systems
- System: ReactorCore Safety API
- Example ID: GQL-0140

## Priority Findings

### Finding 1: Nuclear Safety — Batch Lookup Exposes Cross-Tenant Reactor Safety Data (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA / Batch/Bulk Lookup Endpoints

**Summary:**
Per §5.0 (Pattern 1.9 — batch/bulk lookup endpoints): The `getResource` resolver accepts `resourceId` directly without enforcing tenancy, enabling batch enumeration of reactor safety records. An attacker from `tenant-5175` queried `getResource(id: "R-2140")` and received nuclear safety data belonging to `tenant-48ba`, including `CONFIDENTIAL-517548ba`. In Nuclear / Safety Systems, unauthorized access to safety system data is extremely high-risk, potentially exposing reactor state, coolant system parameters, safety interlock states, and regulatory compliance records.

**Evidence from HAR:**
- Request: `POST https://api.reactorcore-safety-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-5175`
- Query: `getResource(id: "R-2140") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-48ba"`, `ownerId: "other-user-517548ba"`, `sensitiveField: "CONFIDENTIAL-517548ba"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-517548ba`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.9 | Batch lookup, no tenancy enforcement |
| HAR request | x-tenant-id | Attacker tenant-5175 |
| HAR response | tenantId | Cross-tenant reactor safety data tenant-48ba |
| HAR response | sensitiveField | CONFIDENTIAL-517548ba |

## Steps to Reproduce

### Step 1 — getResource on nuclear safety record (HAR)
```bash
curl -s -X POST https://api.reactorcore-safety-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5175" \
  -d '{"query": "query { getResource(id: \"R-2140\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-48ba` reactor safety data returned. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Safety system APIs must have defense-in-depth access controls — multi-factor + network-level restrictions.
3. Rate-limit batch lookups; alert on any cross-tenant probe pattern.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

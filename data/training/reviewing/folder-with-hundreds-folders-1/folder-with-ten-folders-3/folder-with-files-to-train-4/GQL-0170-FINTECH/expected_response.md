# Expected Response

## System
- Domain: FinTech / Payments
- System: PayBridge Transaction API
- Example ID: GQL-0170

## Priority Findings

### Finding 1: FinTech Payments — Resolver Traversal Injection Exposes Cross-Tenant Transaction Data (Pattern 5.2)
**Severity:** Critical
**Category:** Injection / Resolver / Graph Traversal Injection

**Summary:**
Per §5.0 (Pattern 5.2 — resolver/graph traversal injection): The `listResources` resolver traverses the transaction graph accepting a client-supplied `tenantId` filter without tenancy enforcement at each node. An attacker from `tenant-ce72` passed `tenantId: "tenant-439d"` and received payment transaction data belonging to `tenant-439d`, including `CONFIDENTIAL-ce72439d`. In FinTech / Payments, this exposes transaction records, payment method details, and fraud scoring data.

**Evidence from HAR:**
- Request: `POST https://api.paybridge-transactio.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-ce72`
- Query: `listResources(tenantId: "tenant-439d") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-439d"`, `ownerId: "other-user-ce72439d"`, `sensitiveField: "CONFIDENTIAL-ce72439d"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-ce72439d`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 5.2 | Resolver traversal, client tenantId |
| HAR request | tenantId argument | tenant-439d (victim, client-supplied) |
| HAR response | tenantId | tenant-439d transaction data returned |
| HAR response | sensitiveField | CONFIDENTIAL-ce72439d |

## Steps to Reproduce

### Step 1 — listResources traversal injection (HAR)
```bash
curl -s -X POST https://api.paybridge-transactio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ce72" \
  -d '{"query": "query { listResources(tenantId: \"tenant-439d\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-439d` payment data returned. **Secure:** Only `tenant-ce72` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg from `listResources`; enforce at graph traversal level.
2. Resolver: `WHERE tenant_id = $jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

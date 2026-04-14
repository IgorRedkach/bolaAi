# Expected Response

## System
- **Domain:** Waste Management / IoT Fleet
- **System:** CleanRoute IoT Platform
- **Example ID:** GQL-0192

## Priority Findings

### Finding 1: Waste Management IoT — Resolver/Graph Traversal Injection via listResources Exposes Cross-Tenant Fleet Data (Pattern 5.2)
**Severity:** High
**Category:** Injection / Resolver/Graph Traversal Injection

**Summary:**
Per §4.0 (RISK-GQL-192): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 5.2 — resolver/graph traversal injection): the `listResources` resolver accepts a caller-supplied `tenantId` that triggers an unauthorized graph traversal, allowing the attacker to traverse and retrieve IoT fleet data belonging to other tenants. An attacker from `tenant-fe4a` queried `listResources(tenantId: "tenant-02c6")` and received fleet records belonging to `tenant-02c6`, including `CONFIDENTIAL-fe4a02c6`. In Waste Management / IoT Fleet, unauthorized access to route data, vehicle telemetry, and sensor readings enables operational interference and infrastructure mapping.

**Evidence from HAR:**
- Request: `POST https://api.cleanroute-iot-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-fe4a`
- Query: `listResources(tenantId: "tenant-02c6") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-02c6"`, `ownerId: "other-user-fe4a02c6"`, `sensitiveField: "CONFIDENTIAL-fe4a02c6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-fe4a02c6`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-192 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 5.2 | Resolver/graph traversal injection via tenantId argument |
| HAR query | tenantId: "tenant-02c6" | Injected cross-tenant IoT fleet traversal |
| HAR response | tenantId | tenant-02c6 returned to tenant-fe4a |
| HAR response | sensitiveField | CONFIDENTIAL-fe4a02c6 |
| HAR header | x-request-id | req-fe4a02c6 |

## Steps to Reproduce

### Step 1 — listResources graph traversal injection cross-tenant (HAR)
```bash
curl -s -X POST https://api.cleanroute-iot-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-fe4a" \
  -d '{"query": "query { listResources(tenantId: \"tenant-02c6\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-02c6` IoT fleet records including `CONFIDENTIAL-fe4a02c6`. **Secure:** FORBIDDEN — `tenantId` sourced from JWT; only `tenant-fe4a` resources returned.

## Remediation
1. Ignore caller-supplied `tenantId`; enforce `WHERE tenant_id = $jwt.tenantId` in resolver.
2. Validate all graph traversal paths enforce tenant isolation at each resolver node.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

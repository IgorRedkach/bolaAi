# Expected Response

## System
- **Domain:** Smart City / Traffic Orchestration
- **System:** MetroPulse Traffic Orchestration
- **Example ID:** GQL-0204

## Priority Findings

### Finding 1: Smart City Traffic — BOLA via Nested listIntersections Exposes Cross-Tenant Intersection Data (Pattern 1.7)
**Severity:** High
**Category:** BOLA / Nested Resources Without Parent Authorization

**Summary:**
Per §4.0 (RISK-GQL-204): The `getIntersection` resolver fetches by `id` only, without verifying `tenantId` ownership of the parent traffic zone. Per §5.0 (Pattern 1.7 — nested resources without parent authorization): `listIntersections` returns nested intersection nodes belonging to other tenants when a caller-supplied `tenantId` bypasses JWT ownership checks. An attacker from `tenant-dd41` queried `listIntersections(tenantId: "tenant-3801")` and received intersection records belonging to `tenant-3801`, including `CONFIDENTIAL-dd413801`. In Smart City / Traffic Orchestration, unauthorized access to intersection configurations and signal states enables traffic manipulation and public safety incidents.

**Evidence from HAR:**
- Request: `POST https://api.metropulse-traffic-o.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-dd41`
- Query: `listIntersections(tenantId: "tenant-3801") { nodeId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-3801"`, `ownerId: "other-user-dd413801"`, `sensitiveField: "CONFIDENTIAL-dd413801"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-dd413801`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-204 | getIntersection resolver lacks tenantId parent ownership check |
| context.txt §5.0 | Pattern 1.7 | Nested resource (intersection) without parent authorization |
| HAR query | tenantId: "tenant-3801" | Injected cross-tenant intersection filter |
| HAR response | tenantId | tenant-3801 returned to tenant-dd41 |
| HAR response | sensitiveField | CONFIDENTIAL-dd413801 |
| HAR header | x-request-id | req-dd413801 |

## Steps to Reproduce

### Step 1 — listIntersections nested resource BOLA (HAR)
```bash
curl -s -X POST https://api.metropulse-traffic-o.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-dd41" \
  -d '{"query": "query { listIntersections(tenantId: \"tenant-3801\") { nodeId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-3801` intersection records including `CONFIDENTIAL-dd413801`. **Secure:** FORBIDDEN — `tenantId` from JWT; parent traffic zone verified before nested node access.

## Remediation
1. Resolver: `WHERE intersection_id = $id AND tenant_id = $jwt.tenantId` (join through parent traffic zone).
2. Ignore caller-supplied `tenantId`; enforce JWT-derived tenant filter at every nested resolver.
3. Redis cache key: `intersection:{tenantId}:{nodeId}`.

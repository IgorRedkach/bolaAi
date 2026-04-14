# Expected Response

## System
- Domain: Smart City / Traffic Management
- System: MetroPulse Traffic Orchestration
- Example ID: GQL-0104

## Priority Findings

### Finding 1: Traffic Intersection Graph Traversal Injection — Cross-Tenant Traffic Data Exposure (Pattern 5.2)
**Severity:** Critical
**Category:** Injection / Graph Traversal / Safety-Critical

**Summary:**
Per §5.0 (Pattern 5.2 — resolver/graph traversal injection): The `listIntersections` resolver trusts client-supplied `tenantId`, enabling graph traversal across traffic management boundaries. An attacker from `tenant-e25b` passed `tenantId: "tenant-e7c5"` to enumerate traffic intersection records belonging to another city district. The HAR response confirms `getIntersection` returned cross-tenant traffic orchestration data including `nodeId`. Unauthorized access to traffic control data poses public safety risks — manipulation of signal timing, emergency vehicle routing, and congestion management.

**Evidence from HAR:**
- Request: `POST https://api.metropulse-traffic.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-e25b`
- Query: `listIntersections(tenantId: "tenant-e7c5") { nodeId ownerId data { sensitiveField } }`
- Response `200 OK`; `getIntersection`: `tenantId: "tenant-e7c5"`, `ownerId: "other-user-e25be7c5"`, `sensitiveField: "CONFIDENTIAL-e25be7c5"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e25be7c5`
- Note: Domain objects are `Intersection`/`nodeId` with `getIntersection`/`listIntersections`.

## Steps to Reproduce

### Step 1 — Cross-tenant intersection graph traversal (HAR)
```bash
curl -s -X POST https://api.metropulse-traffic.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e25b" \
  -d '{"query": "query VulnerableOp { listIntersections(tenantId: \"tenant-e7c5\") { nodeId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-e25be7c5` traffic data from `tenant-e7c5`. **Secure:** FORBIDDEN.

### Step 2 — Traverse connected intersections
```bash
curl -s -X POST https://api.metropulse-traffic.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e25b" \
  -d '{"query": "query { getIntersection(id: \"I-2104\") { nodeId tenantId items { nodeId tenantId data { sensitiveField } } } }"}'
```
**Vulnerable:** Graph traversal reaches connected intersection nodes from `tenant-e7c5`.

## Remediation
1. `listIntersections` must extract tenantId from JWT — never trust client-supplied argument.
2. Resolver tenant guard on `getIntersection`: `WHERE intersection_id=$id AND tenant_id=$jwt.tenantId`.
3. Re-validate tenantId at each graph node in traversal.
4. Redis cache key: `intersection:{tenantId}:{nodeId}`.

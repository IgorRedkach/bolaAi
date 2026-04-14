# Expected Response

## System
- **Domain:** Automotive / V2X Telematics
- **System:** AetherDrive V2X Telematics
- **Example ID:** GQL-0205

## Priority Findings

### Finding 1: Automotive V2X — BOLA via Predictable ID Enumeration in updateResource Exposes Cross-Tenant Vehicle Data (Pattern 1.8)
**Severity:** High
**Category:** BOLA / Predictable or Sequential IDs

**Summary:**
Per §4.0 (RISK-GQL-205): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.8 — predictable or sequential IDs): resource IDs follow a predictable sequential pattern (`R-2205`) enabling enumeration of cross-tenant vehicle telemetry records. An attacker from `tenant-09d0` submitted `updateResource(id: "R-2205", input: {status: "approved", ownerId: "attacker-09d09c7e"})` against a V2X telematics record belonging to `tenant-9c7e`, receiving `CONFIDENTIAL-09d09c7e`. In Automotive / V2X Telematics, unauthorized access to vehicle location, speed, and safety-critical data enables vehicle tracking, fleet manipulation, and traffic safety incidents.

**Evidence from HAR:**
- Request: `POST https://api.aetherdrive-v2x-tele.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-09d0`
- Mutation: `updateResource(id: "R-2205", input: {status: "approved", ownerId: "attacker-09d09c7e"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-9c7e"`, `ownerId: "other-user-09d09c7e"`, `sensitiveField: "CONFIDENTIAL-09d09c7e"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-09d09c7e`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-205 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.8 | Predictable/sequential IDs enable cross-tenant enumeration |
| HAR mutation | id: "R-2205" | Predictable sequential vehicle telematics ID |
| HAR response | tenantId | tenant-9c7e returned to tenant-09d0 |
| HAR response | sensitiveField | CONFIDENTIAL-09d09c7e |
| HAR header | x-request-id | req-09d09c7e |

## Steps to Reproduce

### Step 1 — updateResource predictable ID enumeration V2X (HAR)
```bash
curl -s -X POST https://api.aetherdrive-v2x-tele.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-09d0" \
  -d '{"query": "mutation { updateResource(id: \"R-2205\", input: {status: \"approved\", ownerId: \"attacker-09d09c7e\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-9c7e` V2X telematics record mutated, returns `CONFIDENTIAL-09d09c7e`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Use non-predictable UUIDs for all vehicle/resource IDs to prevent enumeration.
3. Strip `ownerId` from `ResourceInput`; derive from JWT.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

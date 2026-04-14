# Expected Response

## System
- **Domain:** Industrial IoT / Robotics Fleet
- **System:** ManuControl Robotics Fleet
- **Example ID:** GQL-0207

## Priority Findings

### Finding 1: Industrial IoT Robotics — Cross-Service Identity Drift via listResources Exposes Cross-Tenant Robot Fleet Data (Pattern 1.10)
**Severity:** High
**Category:** BOLA / Cross-Service Identity Propagation Drift

**Summary:**
Per §4.0 (RISK-GQL-207): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.10 — cross-service identity propagation drift): the `listResources` endpoint accepts a caller-supplied `tenantId` that is not re-validated as it propagates across internal robotics microservices, allowing cross-tenant access. An attacker from `tenant-441c` queried `listResources(tenantId: "tenant-ffb6")` and received robotics fleet data belonging to `tenant-ffb6`, including `CONFIDENTIAL-441cffb6`. In Industrial IoT / Robotics Fleet, unauthorized access to robot telemetry, control parameters, and operational schedules enables industrial espionage and potential physical harm.

**Evidence from HAR:**
- Request: `POST https://api.manucontrol-robotics.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-441c`
- Query: `listResources(tenantId: "tenant-ffb6") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-ffb6"`, `ownerId: "other-user-441cffb6"`, `sensitiveField: "CONFIDENTIAL-441cffb6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-441cffb6`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-207 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.10 | Cross-service identity drift — tenantId not re-validated downstream |
| HAR query | tenantId: "tenant-ffb6" | Injected cross-tenant robotics filter |
| HAR response | tenantId | tenant-ffb6 returned to tenant-441c |
| HAR response | sensitiveField | CONFIDENTIAL-441cffb6 |
| HAR header | x-request-id | req-441cffb6 |

## Steps to Reproduce

### Step 1 — listResources cross-service identity drift robotics (HAR)
```bash
curl -s -X POST https://api.manucontrol-robotics.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-441c" \
  -d '{"query": "query { listResources(tenantId: \"tenant-ffb6\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-ffb6` robotics fleet data including `CONFIDENTIAL-441cffb6`. **Secure:** FORBIDDEN — `tenantId` from JWT only.

## Remediation
1. Ignore caller-supplied `tenantId`; each microservice independently validates `tenant_id = $jwt.tenantId`.
2. Pass verified JWT through all inter-service calls; never accept `tenantId` from request body.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

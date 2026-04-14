# Expected Response

## System
- Domain: Insurance / Claims Processing
- System: ClaimsFlow Underwriting API
- Example ID: GQL-0162

## Priority Findings

### Finding 1: Insurance — Batch Lookup Exposes Cross-Tenant Claims via Bulk Endpoint (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA / Batch/Bulk Lookup Endpoints

**Summary:**
Per §5.0 (Pattern 1.9 — batch/bulk lookup endpoints): The `updateClaim` resolver accepts `claimId` without tenancy verification, enabling batch enumeration of claims. An attacker from `tenant-50a8` submitted `updateClaim(id: "C-2162", input: {status: "approved", ownerId: "attacker-50a86d99"})` against an insurance claim belonging to `tenant-6d99`, gaining cross-tenant write access and receiving `CONFIDENTIAL-50a86d99`. In Insurance, this enables unauthorized claim approvals, policy manipulation, and exposure of medical evidence.

**Evidence from HAR:**
- Request: `POST https://api.claimsflow-underwrit.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-50a8`
- Mutation: `updateClaim(id: "C-2162", input: {status: "approved", ownerId: "attacker-50a86d99"}) { claimId status }`
- Response `200 OK`: `tenantId: "tenant-6d99"`, `ownerId: "other-user-50a86d99"`, `sensitiveField: "CONFIDENTIAL-50a86d99"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-50a86d99`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.9 | Batch lookup via updateClaim |
| HAR request | input.ownerId | attacker-50a86d99 (client-injected) |
| HAR response | tenantId | Cross-tenant claim tenant-6d99 |
| HAR response | sensitiveField | CONFIDENTIAL-50a86d99 |

## Steps to Reproduce

### Step 1 — updateClaim cross-tenant (HAR)
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-50a8" \
  -d '{"query": "mutation { updateClaim(id: \"C-2162\", input: {status: \"approved\", ownerId: \"attacker-50a86d99\"}) { claimId status } }"}'
```
**Vulnerable:** `tenant-6d99` claim approved. **Secure:** FORBIDDEN.

## Remediation
1. `updateClaim` resolver: `WHERE claim_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ClaimInput`.
3. Claim state machine: approval requires adjuster role in owning tenant.
4. Redis cache key: `claim:{tenantId}:{claimId}`.

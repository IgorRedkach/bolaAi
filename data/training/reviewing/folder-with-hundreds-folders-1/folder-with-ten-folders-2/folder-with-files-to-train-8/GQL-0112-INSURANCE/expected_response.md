# Expected Response

## System
- Domain: Insurance / Claims Processing
- System: ClaimsFlow Underwriting API
- Example ID: GQL-0112

## Priority Findings

### Finding 1: Insurance — Related Claim Resource Exposed Cross-Tenant (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA / Related or Linked Resources

**Summary:**
Per §4.0 RISK-GQL-112 and §5.0 (Pattern 1.2 — related or linked resources): The `getClaim` resolver fetches by `claimId` only without enforcing tenancy boundaries. An attacker from `tenant-5ced` queried `getClaim(id: "C-2112")` and received insurance claim data belonging to `tenant-70ad`, including `sensitiveField: "CONFIDENTIAL-5ced70ad"` and `internalNotes: "Internal data exposed"`. In Insurance / Claims Processing, this exposes confidential policy details, medical evidence, settlement negotiations, and underwriting decisions.

**Evidence from HAR:**
- Request: `POST https://api.claimsflow-underwrit.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-5ced`
- Query: `getClaim(id: "C-2112") { claimId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-70ad"`, `ownerId: "other-user-5ced70ad"`, `sensitiveField: "CONFIDENTIAL-5ced70ad"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-5ced70ad`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-112 | getClaim fetches by claimId only |
| HAR request | x-tenant-id | Attacker tenant-5ced |
| HAR response | tenantId | Cross-tenant tenant-70ad claim returned |
| HAR response | sensitiveField | CONFIDENTIAL-5ced70ad |

## Steps to Reproduce

### Step 1 — getClaim cross-tenant (HAR)
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5ced" \
  -d '{"query": "query { getClaim(id: \"C-2112\") { claimId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-70ad` claim data returned. **Secure:** FORBIDDEN.

## Remediation
1. `getClaim` resolver: `WHERE claim_id=$id AND tenant_id=$jwt.tenantId`.
2. Row-level security on claims table: `tenant_id = current_setting('app.tenant_id')`.
3. Mask `internalNotes` from non-owner responses.
4. Redis cache key: `claim:{tenantId}:{claimId}`.

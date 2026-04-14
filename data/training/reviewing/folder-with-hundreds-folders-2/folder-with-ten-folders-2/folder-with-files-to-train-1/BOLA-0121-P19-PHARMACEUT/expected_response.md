# Expected Response

## System
- Domain: Pharmaceutical / Clinical Trials
- System: TrialVault ClinicalOps API
- Example ID: BOLA-0121

## Priority Findings

### Finding 1: Batch/bulk lookup endpoints (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.9 (Batch/bulk lookup endpoints).
An authenticated user from `ORG-A2D4` can access or modify objects owned by `ORG-5392`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-A2D4`
- Response body `tenantId`: `ORG-5392` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.trialvault-clin.example.com/api/v1/resources/RES-1121" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A2D4>"
```
Expected: Returns own record with `tenantId: "ORG-A2D4"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.trialvault-clin.example.com/api/v1/resources/RES-2121" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A2D4>"
```
**Vulnerable:** Returns `tenantId: "ORG-5392"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.9
```bash
# Batch lookup
curl -s "/api/v1/resources/batch?ids=RES-2121,RES-3001" -H "Authorization: Bearer <TOKEN_TENANT_ORG-A2D4>"
# Vulnerable: both objects returned regardless of tenant
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

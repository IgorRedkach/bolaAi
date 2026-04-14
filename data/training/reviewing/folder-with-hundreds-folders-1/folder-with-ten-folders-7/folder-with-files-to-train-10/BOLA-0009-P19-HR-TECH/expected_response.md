# Expected Response

## System
- Domain: HR Tech / Talent Acquisition
- System: JobCore Candidate Portal
- Example ID: BOLA-0009

## Priority Findings

### Finding 1: Batch/bulk lookup endpoints (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.9 (Batch/bulk lookup endpoints).
An authenticated user from `ORG-1B09` can access or modify objects owned by `ORG-72AF`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-1B09`
- Response body `tenantId`: `ORG-72AF` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.jobcore-candida.example.com/api/v1/resources/RES-1009" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1B09>"
```
Expected: Returns own record with `tenantId: "ORG-1B09"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.jobcore-candida.example.com/api/v1/resources/RES-2009" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1B09>"
```
**Vulnerable:** Returns `tenantId: "ORG-72AF"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.9
```bash
# Batch lookup
curl -s "/api/v1/resources/batch?ids=RES-2009,RES-3001" -H "Authorization: Bearer <TOKEN_TENANT_ORG-1B09>"
# Vulnerable: both objects returned regardless of tenant
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

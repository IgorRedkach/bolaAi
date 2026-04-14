# Expected Response

## System
- Domain: Aviation / Flight Ops
- System: AeroOps Flight Management
- Example ID: BOLA-6036

## Priority Findings

### Finding 1: Bulk or list endpoints (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.3 (Bulk or list endpoints).
An authenticated user from `ORG-2E64` can access or modify objects owned by `ORG-D388`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-2E64`
- Response body `tenantId`: `ORG-D388` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.aeroops-flight-.example.com/api/v1/resources/RES-7036" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2E64>"
```
Expected: Returns own record with `tenantId: "ORG-2E64"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.aeroops-flight-.example.com/api/v1/resources/RES-8036" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2E64>"
```
**Vulnerable:** Returns `tenantId: "ORG-D388"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.3
```bash
# List endpoint — check if cross-tenant objects appear
curl -s "/api/v1/resources" -H "Authorization: Bearer <TOKEN_TENANT_ORG-2E64>"
# Vulnerable: objects with tenantId=ORG-D388 appear in list
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

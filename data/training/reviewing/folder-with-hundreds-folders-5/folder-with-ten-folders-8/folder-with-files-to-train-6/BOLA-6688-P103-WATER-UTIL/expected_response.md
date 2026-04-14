# Expected Response

## System
- Domain: Water Utilities / Smart Meters
- System: AquaGrid Meter Management
- Example ID: BOLA-6688

## Priority Findings

### Finding 1: Temporary-ID hijacking (Pattern 10.3)
**Severity:** Critical
**Category:** Single-User

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 10.3 (Temporary-ID hijacking).
An authenticated user from `ORG-E64C` can access or modify objects owned by `ORG-7A48`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-E64C`
- Response body `tenantId`: `ORG-7A48` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.aquagrid-meter-.example.com/api/v1/resources/RES-7688" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E64C>"
```
Expected: Returns own record with `tenantId: "ORG-E64C"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.aquagrid-meter-.example.com/api/v1/resources/RES-8688" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E64C>"
```
**Vulnerable:** Returns `tenantId: "ORG-7A48"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 10.3
No specific variant documented for Pattern 10.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

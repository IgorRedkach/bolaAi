# Expected Response

## System
- Domain: Parking / Smart City
- System: ParkIQ Management API
- Example ID: BOLA-5799

## Priority Findings

### Finding 1: ID in path without ownership check (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.1 (ID in path without ownership check).
An authenticated user from `ORG-2117` can access or modify objects owned by `ORG-7710`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-2117`
- Response body `tenantId`: `ORG-7710` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.parkiq-manageme.example.com/api/v1/resources/RES-6799" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2117>"
```
Expected: Returns own record with `tenantId: "ORG-2117"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.parkiq-manageme.example.com/api/v1/resources/RES-7799" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2117>"
```
**Vulnerable:** Returns `tenantId: "ORG-7710"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.1
No specific variant documented for Pattern 1.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

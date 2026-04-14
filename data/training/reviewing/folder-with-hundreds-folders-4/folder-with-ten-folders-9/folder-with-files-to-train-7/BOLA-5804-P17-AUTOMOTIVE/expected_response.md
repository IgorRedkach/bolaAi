# Expected Response

## System
- Domain: Automotive / Connected Car
- System: AetherDrive V2X Telematics
- Example ID: BOLA-5804

## Priority Findings

### Finding 1: Nested resources without parent authorization (Pattern 1.7)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.7 (Nested resources without parent authorization).
An authenticated user from `ORG-A87D` can access or modify objects owned by `ORG-A542`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-A87D`
- Response body `tenantId`: `ORG-A542` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.aetherdrive-v2x.example.com/api/v1/resources/RES-6804" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A87D>"
```
Expected: Returns own record with `tenantId: "ORG-A87D"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.aetherdrive-v2x.example.com/api/v1/resources/RES-7804" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A87D>"
```
**Vulnerable:** Returns `tenantId: "ORG-A542"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.7
No specific variant documented for Pattern 1.7 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

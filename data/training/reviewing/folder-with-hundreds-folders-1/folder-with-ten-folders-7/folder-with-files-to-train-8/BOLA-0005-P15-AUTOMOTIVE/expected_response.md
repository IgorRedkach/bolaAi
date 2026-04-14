# Expected Response

## System
- Domain: Automotive / Connected Car
- System: AetherDrive V2X Telematics
- Example ID: BOLA-0005

## Priority Findings

### Finding 1: Multi-tenant / cross-tenant access (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.5 (Multi-tenant / cross-tenant access).
An authenticated user from `ORG-EB0D` can access or modify objects owned by `ORG-AF87`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-EB0D`
- Response body `tenantId`: `ORG-AF87` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.aetherdrive-v2x.example.com/api/v1/resources/RES-1005" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-EB0D>"
```
Expected: Returns own record with `tenantId: "ORG-EB0D"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.aetherdrive-v2x.example.com/api/v1/resources/RES-2005" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-EB0D>"
```
**Vulnerable:** Returns `tenantId: "ORG-AF87"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.5
No specific variant documented for Pattern 1.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

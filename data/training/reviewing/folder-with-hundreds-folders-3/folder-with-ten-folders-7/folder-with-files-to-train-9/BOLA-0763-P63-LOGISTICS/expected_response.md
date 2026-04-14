# Expected Response

## System
- Domain: Logistics / Supply Chain
- System: FreightLens Tracking API
- Example ID: BOLA-0763

## Priority Findings

### Finding 1: Default credentials and unnecessary services (Pattern 6.3)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.3 (Default credentials and unnecessary services).
An authenticated user from `ORG-D3EE` can access or modify objects owned by `ORG-6134`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D3EE`
- Response body `tenantId`: `ORG-6134` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/resources/RES-1763" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3EE>"
```
Expected: Returns own record with `tenantId: "ORG-D3EE"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/resources/RES-2763" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3EE>"
```
**Vulnerable:** Returns `tenantId: "ORG-6134"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.3
No specific variant documented for Pattern 6.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

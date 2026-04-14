# Expected Response

## System
- Domain: Waste Management / Smart Bins
- System: CleanRoute IoT Platform
- Example ID: BOLA-0892

## Priority Findings

### Finding 1: Parameter escalation (own session scope extension) (Pattern 10.2)
**Severity:** Critical
**Category:** Single-User

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 10.2 (Parameter escalation (own session scope extension)).
An authenticated user from `ORG-1158` can access or modify objects owned by `ORG-5FC6`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-1158`
- Response body `tenantId`: `ORG-5FC6` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.cleanroute-iot-.example.com/api/v1/resources/RES-1892" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1158>"
```
Expected: Returns own record with `tenantId: "ORG-1158"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.cleanroute-iot-.example.com/api/v1/resources/RES-2892" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1158>"
```
**Vulnerable:** Returns `tenantId: "ORG-5FC6"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 10.2
No specific variant documented for Pattern 10.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

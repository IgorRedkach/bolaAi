# Expected Response

## System
- Domain: Waste Management / Smart Bins
- System: CleanRoute IoT Platform
- Example ID: BOLA-5341

## Priority Findings

### Finding 1: Critical Infrastructure interface exposure (Pattern 2.5)
**Severity:** Critical
**Category:** BAC

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 2.5 (Critical Infrastructure interface exposure).
An authenticated user from `ORG-D1C2` can access or modify objects owned by `ORG-9087`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D1C2`
- Response body `tenantId`: `ORG-9087` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.cleanroute-iot-.example.com/api/v1/resources/RES-6341" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D1C2>"
```
Expected: Returns own record with `tenantId: "ORG-D1C2"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.cleanroute-iot-.example.com/api/v1/resources/RES-7341" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D1C2>"
```
**Vulnerable:** Returns `tenantId: "ORG-9087"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 2.5
No specific variant documented for Pattern 2.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

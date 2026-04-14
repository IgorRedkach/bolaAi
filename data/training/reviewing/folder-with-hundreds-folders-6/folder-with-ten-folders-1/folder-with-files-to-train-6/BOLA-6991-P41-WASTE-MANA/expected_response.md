# Expected Response

## System
- Domain: Waste Management / Smart Bins
- System: CleanRoute IoT Platform
- Example ID: BOLA-6991

## Priority Findings

### Finding 1: Confused deputy / brokerage failures (Pattern 4.1)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.1 (Confused deputy / brokerage failures).
An authenticated user from `ORG-A80E` can access or modify objects owned by `ORG-2F44`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-A80E`
- Response body `tenantId`: `ORG-2F44` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.cleanroute-iot-.example.com/api/v1/resources/RES-7991" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A80E>"
```
Expected: Returns own record with `tenantId: "ORG-A80E"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.cleanroute-iot-.example.com/api/v1/resources/RES-8991" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A80E>"
```
**Vulnerable:** Returns `tenantId: "ORG-2F44"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.1
No specific variant documented for Pattern 4.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

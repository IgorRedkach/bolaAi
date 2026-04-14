# Expected Response

## System
- Domain: Mining / Resource Extraction
- System: OreTrack Fleet Management
- Example ID: BOLA-6274

## Priority Findings

### Finding 1: Nested resources without parent authorization (Pattern 1.7)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.7 (Nested resources without parent authorization).
An authenticated user from `ORG-F488` can access or modify objects owned by `ORG-9CFC`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-F488`
- Response body `tenantId`: `ORG-9CFC` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.oretrack-fleet-.example.com/api/v1/resources/RES-7274" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F488>"
```
Expected: Returns own record with `tenantId: "ORG-F488"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.oretrack-fleet-.example.com/api/v1/resources/RES-8274" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F488>"
```
**Vulnerable:** Returns `tenantId: "ORG-9CFC"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.7
No specific variant documented for Pattern 1.7 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

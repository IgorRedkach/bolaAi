# Expected Response

## System
- Domain: Travel / GDS
- System: SkyPort Global Distribution
- Example ID: BOLA-6167

## Priority Findings

### Finding 1: GraphQL: single endpoint vulnerabilities (Pattern 9.1)
**Severity:** Critical
**Category:** Platform

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 9.1 (GraphQL: single endpoint vulnerabilities).
An authenticated user from `ORG-4FA5` can access or modify objects owned by `ORG-F61E`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-4FA5`
- Response body `tenantId`: `ORG-F61E` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.skyport-global-.example.com/api/v1/resources/RES-7167" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-4FA5>"
```
Expected: Returns own record with `tenantId: "ORG-4FA5"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.skyport-global-.example.com/api/v1/resources/RES-8167" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-4FA5>"
```
**Vulnerable:** Returns `tenantId: "ORG-F61E"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 9.1
No specific variant documented for Pattern 9.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

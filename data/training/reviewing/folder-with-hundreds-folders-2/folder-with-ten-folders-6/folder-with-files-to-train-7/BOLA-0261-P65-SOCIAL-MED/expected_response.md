# Expected Response

## System
- Domain: Social Media / Identity Graph
- System: Horizon Social Graph API
- Example ID: BOLA-0261

## Priority Findings

### Finding 1: Shadow AI and ungoverned ML endpoints (Pattern 6.5)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.5 (Shadow AI and ungoverned ML endpoints).
An authenticated user from `ORG-2671` can access or modify objects owned by `ORG-C68B`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-2671`
- Response body `tenantId`: `ORG-C68B` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.horizon-social-.example.com/api/v1/resources/RES-1261" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2671>"
```
Expected: Returns own record with `tenantId: "ORG-2671"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.horizon-social-.example.com/api/v1/resources/RES-2261" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2671>"
```
**Vulnerable:** Returns `tenantId: "ORG-C68B"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.5
No specific variant documented for Pattern 6.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

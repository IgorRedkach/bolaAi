# Expected Response

## System
- Domain: Mining / Resource Extraction
- System: OreTrack Fleet Management
- Example ID: BOLA-0975

## Priority Findings

### Finding 1: Unsecured multi-step critical workflows (Pattern 3.5)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.5 (Unsecured multi-step critical workflows).
An authenticated user from `ORG-843B` can access or modify objects owned by `ORG-4E7A`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-843B`
- Response body `tenantId`: `ORG-4E7A` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.oretrack-fleet-.example.com/api/v1/resources/RES-1975" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-843B>"
```
Expected: Returns own record with `tenantId: "ORG-843B"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.oretrack-fleet-.example.com/api/v1/resources/RES-2975" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-843B>"
```
**Vulnerable:** Returns `tenantId: "ORG-4E7A"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.5
No specific variant documented for Pattern 3.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

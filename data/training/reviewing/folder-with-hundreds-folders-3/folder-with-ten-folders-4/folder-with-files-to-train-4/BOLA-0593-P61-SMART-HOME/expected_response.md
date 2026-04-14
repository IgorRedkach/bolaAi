# Expected Response

## System
- Domain: Smart Home / Building Automation
- System: NeoBuild BAS Platform
- Example ID: BOLA-0593

## Priority Findings

### Finding 1: Schema/relationship over-exposure (Pattern 6.1)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.1 (Schema/relationship over-exposure).
An authenticated user from `ORG-F644` can access or modify objects owned by `ORG-771E`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-F644`
- Response body `tenantId`: `ORG-771E` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.neobuild-bas-pl.example.com/api/v1/resources/RES-1593" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F644>"
```
Expected: Returns own record with `tenantId: "ORG-F644"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.neobuild-bas-pl.example.com/api/v1/resources/RES-2593" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F644>"
```
**Vulnerable:** Returns `tenantId: "ORG-771E"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.1
No specific variant documented for Pattern 6.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Construction / BIM Platform
- System: BuildCore BIM Collaboration
- Example ID: BOLA-5827

## Priority Findings

### Finding 1: Cloud storage bucket and network exposure (Pattern 6.4)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.4 (Cloud storage bucket and network exposure).
An authenticated user from `ORG-31E3` can access or modify objects owned by `ORG-D4B3`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-31E3`
- Response body `tenantId`: `ORG-D4B3` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.buildcore-bim-c.example.com/api/v1/resources/RES-6827" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-31E3>"
```
Expected: Returns own record with `tenantId: "ORG-31E3"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.buildcore-bim-c.example.com/api/v1/resources/RES-7827" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-31E3>"
```
**Vulnerable:** Returns `tenantId: "ORG-D4B3"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.4
No specific variant documented for Pattern 6.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

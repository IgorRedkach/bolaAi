# Expected Response

## System
- Domain: Construction / BIM Platform
- System: BuildCore BIM Collaboration
- Example ID: BOLA-5377

## Priority Findings

### Finding 1: Related or linked resources (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.2 (Related or linked resources).
An authenticated user from `ORG-A8EF` can access or modify objects owned by `ORG-1708`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-A8EF`
- Response body `tenantId`: `ORG-1708` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.buildcore-bim-c.example.com/api/v1/resources/RES-6377" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A8EF>"
```
Expected: Returns own record with `tenantId: "ORG-A8EF"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.buildcore-bim-c.example.com/api/v1/resources/RES-7377" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A8EF>"
```
**Vulnerable:** Returns `tenantId: "ORG-1708"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.2
No specific variant documented for Pattern 1.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

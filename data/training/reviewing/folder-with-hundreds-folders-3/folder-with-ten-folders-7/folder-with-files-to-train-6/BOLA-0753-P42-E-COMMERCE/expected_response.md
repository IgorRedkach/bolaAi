# Expected Response

## System
- Domain: E-Commerce / Marketplace
- System: ShopGrid Marketplace API
- Example ID: BOLA-0753

## Priority Findings

### Finding 1: Persistence poisoning via lifecycle actions (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.2 (Persistence poisoning via lifecycle actions).
An authenticated user from `ORG-3AEF` can access or modify objects owned by `ORG-FA89`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-3AEF`
- Response body `tenantId`: `ORG-FA89` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.shopgrid-market.example.com/api/v1/resources/RES-1753" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3AEF>"
```
Expected: Returns own record with `tenantId: "ORG-3AEF"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.shopgrid-market.example.com/api/v1/resources/RES-2753" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3AEF>"
```
**Vulnerable:** Returns `tenantId: "ORG-FA89"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.2
No specific variant documented for Pattern 4.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

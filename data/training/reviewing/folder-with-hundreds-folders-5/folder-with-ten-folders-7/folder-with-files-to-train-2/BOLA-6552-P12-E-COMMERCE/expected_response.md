# Expected Response

## System
- Domain: E-Commerce / Marketplace
- System: ShopGrid Marketplace API
- Example ID: BOLA-6552

## Priority Findings

### Finding 1: Related or linked resources (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.2 (Related or linked resources).
An authenticated user from `ORG-CFA1` can access or modify objects owned by `ORG-67E2`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-CFA1`
- Response body `tenantId`: `ORG-67E2` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.shopgrid-market.example.com/api/v1/resources/RES-7552" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CFA1>"
```
Expected: Returns own record with `tenantId: "ORG-CFA1"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.shopgrid-market.example.com/api/v1/resources/RES-8552" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CFA1>"
```
**Vulnerable:** Returns `tenantId: "ORG-67E2"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.2
No specific variant documented for Pattern 1.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

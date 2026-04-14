# Expected Response

## System
- Domain: E-Commerce / Marketplace
- System: ShopGrid Marketplace API
- Example ID: BOLA-6852

## Priority Findings

### Finding 1: Integrity downgrade via versioning (Pattern 4.3)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.3 (Integrity downgrade via versioning).
An authenticated user from `ORG-22F7` can access or modify objects owned by `ORG-B2E7`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-22F7`
- Response body `tenantId`: `ORG-B2E7` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.shopgrid-market.example.com/api/v1/resources/RES-7852" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-22F7>"
```
Expected: Returns own record with `tenantId: "ORG-22F7"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.shopgrid-market.example.com/api/v1/resources/RES-8852" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-22F7>"
```
**Vulnerable:** Returns `tenantId: "ORG-B2E7"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.3
No specific variant documented for Pattern 4.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

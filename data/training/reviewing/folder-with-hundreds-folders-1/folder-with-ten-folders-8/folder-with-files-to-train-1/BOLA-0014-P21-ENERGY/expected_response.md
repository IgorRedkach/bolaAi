# Expected Response

## System
- Domain: Energy / Utilities / Smart Grid
- System: PowerGrid Customer Billing API
- Example ID: BOLA-0014

## Priority Findings

### Finding 1: Functional pivot (vertical/horizontal) (Pattern 2.1)
**Severity:** Critical
**Category:** BAC

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 2.1 (Functional pivot (vertical/horizontal)).
An authenticated user from `ORG-C4CF` can access or modify objects owned by `ORG-F76B`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-C4CF`
- Response body `tenantId`: `ORG-F76B` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.powergrid-custo.example.com/api/v1/resources/RES-1014" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-C4CF>"
```
Expected: Returns own record with `tenantId: "ORG-C4CF"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.powergrid-custo.example.com/api/v1/resources/RES-2014" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-C4CF>"
```
**Vulnerable:** Returns `tenantId: "ORG-F76B"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 2.1
No specific variant documented for Pattern 2.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Energy / Utilities / Smart Grid
- System: PowerGrid Customer Billing API
- Example ID: BOLA-5063

## Priority Findings

### Finding 1: Unsecured multi-step critical workflows (Pattern 3.5)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.5 (Unsecured multi-step critical workflows).
An authenticated user from `ORG-6A1B` can access or modify objects owned by `ORG-0E2B`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-6A1B`
- Response body `tenantId`: `ORG-0E2B` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.powergrid-custo.example.com/api/v1/resources/RES-6063" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6A1B>"
```
Expected: Returns own record with `tenantId: "ORG-6A1B"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.powergrid-custo.example.com/api/v1/resources/RES-7063" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6A1B>"
```
**Vulnerable:** Returns `tenantId: "ORG-0E2B"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.5
No specific variant documented for Pattern 3.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

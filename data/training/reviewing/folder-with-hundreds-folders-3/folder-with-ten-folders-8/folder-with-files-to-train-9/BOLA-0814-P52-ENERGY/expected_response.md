# Expected Response

## System
- Domain: Energy / Utilities / Smart Grid
- System: PowerGrid Customer Billing API
- Example ID: BOLA-0814

## Priority Findings

### Finding 1: Resolver/graph traversal injection (Pattern 5.2)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.2 (Resolver/graph traversal injection).
An authenticated user from `ORG-7AC7` can access or modify objects owned by `ORG-7DFA`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-7AC7`
- Response body `tenantId`: `ORG-7DFA` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.powergrid-custo.example.com/api/v1/resources/RES-1814" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7AC7>"
```
Expected: Returns own record with `tenantId: "ORG-7AC7"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.powergrid-custo.example.com/api/v1/resources/RES-2814" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7AC7>"
```
**Vulnerable:** Returns `tenantId: "ORG-7DFA"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.2
No specific variant documented for Pattern 5.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Food & Beverage / FMCG
- System: TraceOrigin Supply API
- Example ID: BOLA-0579

## Priority Findings

### Finding 1: Client-assumed authority (Pattern 3.1)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.1 (Client-assumed authority).
An authenticated user from `ORG-878D` can access or modify objects owned by `ORG-C025`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-878D`
- Response body `tenantId`: `ORG-C025` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.traceorigin-sup.example.com/api/v1/resources/RES-1579" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-878D>"
```
Expected: Returns own record with `tenantId: "ORG-878D"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.traceorigin-sup.example.com/api/v1/resources/RES-2579" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-878D>"
```
**Vulnerable:** Returns `tenantId: "ORG-C025"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.1
No specific variant documented for Pattern 3.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

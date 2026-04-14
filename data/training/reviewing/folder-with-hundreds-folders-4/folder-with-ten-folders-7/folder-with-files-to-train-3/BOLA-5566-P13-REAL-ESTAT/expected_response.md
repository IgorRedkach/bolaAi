# Expected Response

## System
- Domain: Real Estate / PropTech
- System: EstateFlow Property API
- Example ID: BOLA-5566

## Priority Findings

### Finding 1: Bulk or list endpoints (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.3 (Bulk or list endpoints).
An authenticated user from `ORG-D3C2` can access or modify objects owned by `ORG-FEA6`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D3C2`
- Response body `tenantId`: `ORG-FEA6` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.estateflow-prop.example.com/api/v1/resources/RES-6566" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3C2>"
```
Expected: Returns own record with `tenantId: "ORG-D3C2"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.estateflow-prop.example.com/api/v1/resources/RES-7566" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3C2>"
```
**Vulnerable:** Returns `tenantId: "ORG-FEA6"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.3
```bash
# List endpoint — check if cross-tenant objects appear
curl -s "/api/v1/resources" -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3C2>"
# Vulnerable: objects with tenantId=ORG-FEA6 appear in list
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

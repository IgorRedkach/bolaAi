# Expected Response

## System
- Domain: B2B SaaS / CRM
- System: PipelinePro Sales API
- Example ID: BOLA-6083

## Priority Findings

### Finding 1: Bulk or list endpoints (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.3 (Bulk or list endpoints).
An authenticated user from `ORG-810C` can access or modify objects owned by `ORG-759B`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-810C`
- Response body `tenantId`: `ORG-759B` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v1/resources/RES-7083" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-810C>"
```
Expected: Returns own record with `tenantId: "ORG-810C"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v1/resources/RES-8083" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-810C>"
```
**Vulnerable:** Returns `tenantId: "ORG-759B"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.3
```bash
# List endpoint — check if cross-tenant objects appear
curl -s "/api/v1/resources" -H "Authorization: Bearer <TOKEN_TENANT_ORG-810C>"
# Vulnerable: objects with tenantId=ORG-759B appear in list
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

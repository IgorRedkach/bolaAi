# Expected Response

## System
- Domain: B2B SaaS / CRM
- System: PipelinePro Sales API
- Example ID: BOLA-0684

## Priority Findings

### Finding 1: Mass assignment via object fields (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.12 (Mass assignment via object fields).
An authenticated user from `ORG-3CE8` can access or modify objects owned by `ORG-C09A`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-3CE8`
- Response body `tenantId`: `ORG-C09A` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v1/resources/RES-1684" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3CE8>"
```
Expected: Returns own record with `tenantId: "ORG-3CE8"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v1/resources/RES-2684" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3CE8>"
```
**Vulnerable:** Returns `tenantId: "ORG-C09A"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.12
```bash
# Mass assignment
curl -s -X PATCH "/api/v1/resources/RES-2684" -H "Authorization: Bearer <TOKEN_TENANT_ORG-3CE8>" -d '{"ownerId":"attacker","tenantId":"ORG-3CE8"}'
# Vulnerable: ownership transferred
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

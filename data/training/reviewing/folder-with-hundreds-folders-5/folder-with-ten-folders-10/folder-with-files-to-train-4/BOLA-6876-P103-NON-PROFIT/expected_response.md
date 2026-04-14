# Expected Response

## System
- Domain: Non-Profit / Grant Management
- System: GrantFlow CRM API
- Example ID: BOLA-6876

## Priority Findings

### Finding 1: Temporary-ID hijacking (Pattern 10.3)
**Severity:** Critical
**Category:** Single-User

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 10.3 (Temporary-ID hijacking).
An authenticated user from `ORG-D259` can access or modify objects owned by `ORG-5D31`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D259`
- Response body `tenantId`: `ORG-5D31` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/resources/RES-7876" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D259>"
```
Expected: Returns own record with `tenantId: "ORG-D259"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/resources/RES-8876" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D259>"
```
**Vulnerable:** Returns `tenantId: "ORG-5D31"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 10.3
No specific variant documented for Pattern 10.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Non-Profit / Grant Management
- System: GrantFlow CRM API
- Example ID: BOLA-5176

## Priority Findings

### Finding 1: Fail-open on timeout (Pattern 8.2)
**Severity:** Critical
**Category:** Exceptional

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 8.2 (Fail-open on timeout).
An authenticated user from `ORG-1335` can access or modify objects owned by `ORG-E7C2`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-1335`
- Response body `tenantId`: `ORG-E7C2` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/resources/RES-6176" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1335>"
```
Expected: Returns own record with `tenantId: "ORG-1335"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/resources/RES-7176" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1335>"
```
**Vulnerable:** Returns `tenantId: "ORG-E7C2"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 8.2
No specific variant documented for Pattern 8.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Non-Profit / Grant Management
- System: GrantFlow CRM API
- Example ID: BOLA-6126

## Priority Findings

### Finding 1: Draft / non-published resource access (Pattern 10.5)
**Severity:** Critical
**Category:** Single-User

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 10.5 (Draft / non-published resource access).
An authenticated user from `ORG-E460` can access or modify objects owned by `ORG-FDCB`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-E460`
- Response body `tenantId`: `ORG-FDCB` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/resources/RES-7126" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E460>"
```
Expected: Returns own record with `tenantId: "ORG-E460"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/resources/RES-8126" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E460>"
```
**Vulnerable:** Returns `tenantId: "ORG-FDCB"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 10.5
No specific variant documented for Pattern 10.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

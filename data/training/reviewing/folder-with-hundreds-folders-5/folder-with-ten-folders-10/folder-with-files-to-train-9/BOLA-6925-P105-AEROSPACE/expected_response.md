# Expected Response

## System
- Domain: Aerospace / MRO
- System: WingTech Maintenance Portal
- Example ID: BOLA-6925

## Priority Findings

### Finding 1: Draft / non-published resource access (Pattern 10.5)
**Severity:** Critical
**Category:** Single-User

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 10.5 (Draft / non-published resource access).
An authenticated user from `ORG-6643` can access or modify objects owned by `ORG-A96A`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-6643`
- Response body `tenantId`: `ORG-A96A` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/resources/RES-7925" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6643>"
```
Expected: Returns own record with `tenantId: "ORG-6643"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/resources/RES-8925" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6643>"
```
**Vulnerable:** Returns `tenantId: "ORG-A96A"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 10.5
No specific variant documented for Pattern 10.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

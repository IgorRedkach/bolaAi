# Expected Response

## System
- Domain: Government / Public Safety
- System: FirstResponse CAD Integration
- Example ID: BOLA-6507

## Priority Findings

### Finding 1: Third-party or storage APIs (Pattern 1.4)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.4 (Third-party or storage APIs).
An authenticated user from `ORG-E95A` can access or modify objects owned by `ORG-4EB6`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-E95A`
- Response body `tenantId`: `ORG-4EB6` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.firstresponse-c.example.com/api/v1/resources/RES-7507" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E95A>"
```
Expected: Returns own record with `tenantId: "ORG-E95A"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.firstresponse-c.example.com/api/v1/resources/RES-8507" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E95A>"
```
**Vulnerable:** Returns `tenantId: "ORG-4EB6"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.4
No specific variant documented for Pattern 1.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

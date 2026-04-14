# Expected Response

## System
- Domain: Document Signing / eSign
- System: SignFlow eSign Platform
- Example ID: BOLA-5746

## Priority Findings

### Finding 1: Smart Cities and IoT Networks (Pattern 9.5)
**Severity:** Critical
**Category:** Platform

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 9.5 (Smart Cities and IoT Networks).
An authenticated user from `ORG-6C9D` can access or modify objects owned by `ORG-36BC`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-6C9D`
- Response body `tenantId`: `ORG-36BC` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.signflow-esign-.example.com/api/v1/resources/RES-6746" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6C9D>"
```
Expected: Returns own record with `tenantId: "ORG-6C9D"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.signflow-esign-.example.com/api/v1/resources/RES-7746" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-6C9D>"
```
**Vulnerable:** Returns `tenantId: "ORG-36BC"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 9.5
No specific variant documented for Pattern 9.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

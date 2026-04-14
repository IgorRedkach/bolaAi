# Expected Response

## System
- Domain: Document Signing / eSign
- System: SignFlow eSign Platform
- Example ID: BOLA-0197

## Priority Findings

### Finding 1: Authorization-bypass injection (Pattern 5.1)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.1 (Authorization-bypass injection).
An authenticated user from `ORG-F8C7` can access or modify objects owned by `ORG-6FEB`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-F8C7`
- Response body `tenantId`: `ORG-6FEB` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.signflow-esign-.example.com/api/v1/resources/RES-1197" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F8C7>"
```
Expected: Returns own record with `tenantId: "ORG-F8C7"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.signflow-esign-.example.com/api/v1/resources/RES-2197" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F8C7>"
```
**Vulnerable:** Returns `tenantId: "ORG-6FEB"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.1
No specific variant documented for Pattern 5.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Document Signing / eSign
- System: SignFlow eSign Platform
- Example ID: BOLA-5496

## Priority Findings

### Finding 1: Verbose error feedback (Pattern 6.2)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.2 (Verbose error feedback).
An authenticated user from `ORG-ED02` can access or modify objects owned by `ORG-6EA3`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-ED02`
- Response body `tenantId`: `ORG-6EA3` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.signflow-esign-.example.com/api/v1/resources/RES-6496" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-ED02>"
```
Expected: Returns own record with `tenantId: "ORG-ED02"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.signflow-esign-.example.com/api/v1/resources/RES-7496" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-ED02>"
```
**Vulnerable:** Returns `tenantId: "ORG-6EA3"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.2
No specific variant documented for Pattern 6.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

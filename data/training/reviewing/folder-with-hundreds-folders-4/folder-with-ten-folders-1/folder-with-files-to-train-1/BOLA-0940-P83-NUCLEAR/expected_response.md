# Expected Response

## System
- Domain: Nuclear / Safety Systems
- System: ReactorCore Safety API
- Example ID: BOLA-0940

## Priority Findings

### Finding 1: Fail-open on security checks (Pattern 8.3)
**Severity:** Critical
**Category:** Exceptional

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 8.3 (Fail-open on security checks).
An authenticated user from `ORG-D0DC` can access or modify objects owned by `ORG-D46B`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D0DC`
- Response body `tenantId`: `ORG-D46B` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.reactorcore-saf.example.com/api/v1/resources/RES-1940" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D0DC>"
```
Expected: Returns own record with `tenantId: "ORG-D0DC"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.reactorcore-saf.example.com/api/v1/resources/RES-2940" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D0DC>"
```
**Vulnerable:** Returns `tenantId: "ORG-D46B"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 8.3
No specific variant documented for Pattern 8.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

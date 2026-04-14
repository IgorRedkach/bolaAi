# Expected Response

## System
- Domain: Nuclear / Safety Systems
- System: ReactorCore Safety API
- Example ID: BOLA-0990

## Priority Findings

### Finding 1: Operational PII/PHI leakage (Pattern 7.1)
**Severity:** Critical
**Category:** Logging Failures

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 7.1 (Operational PII/PHI leakage).
An authenticated user from `ORG-1978` can access or modify objects owned by `ORG-5811`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-1978`
- Response body `tenantId`: `ORG-5811` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.reactorcore-saf.example.com/api/v1/resources/RES-1990" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1978>"
```
Expected: Returns own record with `tenantId: "ORG-1978"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.reactorcore-saf.example.com/api/v1/resources/RES-2990" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1978>"
```
**Vulnerable:** Returns `tenantId: "ORG-5811"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 7.1
No specific variant documented for Pattern 7.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

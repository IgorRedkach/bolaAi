# Expected Response

## System
- Domain: HR / Payroll Processing
- System: WageFlow Payroll API
- Example ID: BOLA-5345

## Priority Findings

### Finding 1: Unsecured multi-step critical workflows (Pattern 3.5)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.5 (Unsecured multi-step critical workflows).
An authenticated user from `ORG-D6DB` can access or modify objects owned by `ORG-CA90`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D6DB`
- Response body `tenantId`: `ORG-CA90` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-6345" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D6DB>"
```
Expected: Returns own record with `tenantId: "ORG-D6DB"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-7345" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D6DB>"
```
**Vulnerable:** Returns `tenantId: "ORG-CA90"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.5
No specific variant documented for Pattern 3.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

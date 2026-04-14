# Expected Response

## System
- Domain: HR / Payroll Processing
- System: WageFlow Payroll API
- Example ID: BOLA-5445

## Priority Findings

### Finding 1: Authorization-bypass injection (Pattern 5.1)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.1 (Authorization-bypass injection).
An authenticated user from `ORG-D4AD` can access or modify objects owned by `ORG-A4A0`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D4AD`
- Response body `tenantId`: `ORG-A4A0` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-6445" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D4AD>"
```
Expected: Returns own record with `tenantId: "ORG-D4AD"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-7445" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D4AD>"
```
**Vulnerable:** Returns `tenantId: "ORG-A4A0"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.1
No specific variant documented for Pattern 5.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: HR / Payroll Processing
- System: WageFlow Payroll API
- Example ID: BOLA-5545

## Priority Findings

### Finding 1: Cloud storage bucket and network exposure (Pattern 6.4)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.4 (Cloud storage bucket and network exposure).
An authenticated user from `ORG-17AA` can access or modify objects owned by `ORG-A646`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-17AA`
- Response body `tenantId`: `ORG-A646` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-6545" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-17AA>"
```
Expected: Returns own record with `tenantId: "ORG-17AA"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-7545" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-17AA>"
```
**Vulnerable:** Returns `tenantId: "ORG-A646"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.4
No specific variant documented for Pattern 6.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

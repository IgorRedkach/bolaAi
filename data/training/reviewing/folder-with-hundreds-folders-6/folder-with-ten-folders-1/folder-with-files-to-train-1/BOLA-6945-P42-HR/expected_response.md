# Expected Response

## System
- Domain: HR / Payroll Processing
- System: WageFlow Payroll API
- Example ID: BOLA-6945

## Priority Findings

### Finding 1: Persistence poisoning via lifecycle actions (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.2 (Persistence poisoning via lifecycle actions).
An authenticated user from `ORG-8CD9` can access or modify objects owned by `ORG-DD07`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-8CD9`
- Response body `tenantId`: `ORG-DD07` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-7945" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8CD9>"
```
Expected: Returns own record with `tenantId: "ORG-8CD9"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.wageflow-payrol.example.com/api/v1/resources/RES-8945" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8CD9>"
```
**Vulnerable:** Returns `tenantId: "ORG-DD07"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.2
No specific variant documented for Pattern 4.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

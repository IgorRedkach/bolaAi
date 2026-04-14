# Expected Response

## System
- Domain: Food & Beverage / FMCG
- System: TraceOrigin Supply API
- Example ID: BOLA-6628

## Priority Findings

### Finding 1: Operational PII/PHI leakage (Pattern 7.1)
**Severity:** Critical
**Category:** Logging Failures

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 7.1 (Operational PII/PHI leakage).
An authenticated user from `ORG-CE5E` can access or modify objects owned by `ORG-59BC`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-CE5E`
- Response body `tenantId`: `ORG-59BC` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.traceorigin-sup.example.com/api/v1/resources/RES-7628" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CE5E>"
```
Expected: Returns own record with `tenantId: "ORG-CE5E"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.traceorigin-sup.example.com/api/v1/resources/RES-8628" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CE5E>"
```
**Vulnerable:** Returns `tenantId: "ORG-59BC"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 7.1
No specific variant documented for Pattern 7.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

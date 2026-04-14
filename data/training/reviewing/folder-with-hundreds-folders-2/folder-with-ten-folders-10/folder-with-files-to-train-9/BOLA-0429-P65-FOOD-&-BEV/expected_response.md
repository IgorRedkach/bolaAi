# Expected Response

## System
- Domain: Food & Beverage / FMCG
- System: TraceOrigin Supply API
- Example ID: BOLA-0429

## Priority Findings

### Finding 1: Shadow AI and ungoverned ML endpoints (Pattern 6.5)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.5 (Shadow AI and ungoverned ML endpoints).
An authenticated user from `ORG-1439` can access or modify objects owned by `ORG-AEF6`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-1439`
- Response body `tenantId`: `ORG-AEF6` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.traceorigin-sup.example.com/api/v1/resources/RES-1429" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1439>"
```
Expected: Returns own record with `tenantId: "ORG-1439"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.traceorigin-sup.example.com/api/v1/resources/RES-2429" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1439>"
```
**Vulnerable:** Returns `tenantId: "ORG-AEF6"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.5
No specific variant documented for Pattern 6.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

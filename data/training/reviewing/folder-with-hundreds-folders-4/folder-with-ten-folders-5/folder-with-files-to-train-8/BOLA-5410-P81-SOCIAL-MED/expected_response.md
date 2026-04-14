# Expected Response

## System
- Domain: Social Media / Identity Graph
- System: Horizon Social Graph API
- Example ID: BOLA-5410

## Priority Findings

### Finding 1: Race condition / concurrency gaps (Pattern 8.1)
**Severity:** Critical
**Category:** Exceptional

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 8.1 (Race condition / concurrency gaps).
An authenticated user from `ORG-DE35` can access or modify objects owned by `ORG-DFA6`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-DE35`
- Response body `tenantId`: `ORG-DFA6` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.horizon-social-.example.com/api/v1/resources/RES-6410" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-DE35>"
```
Expected: Returns own record with `tenantId: "ORG-DE35"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.horizon-social-.example.com/api/v1/resources/RES-7410" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-DE35>"
```
**Vulnerable:** Returns `tenantId: "ORG-DFA6"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 8.1
No specific variant documented for Pattern 8.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

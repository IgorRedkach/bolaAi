# Expected Response

## System
- Domain: Insurance / Claims Processing
- System: ClaimsFlow Underwriting API
- Example ID: BOLA-5461

## Priority Findings

### Finding 1: State corruption in critical transactions (Pattern 8.5)
**Severity:** Critical
**Category:** Exceptional

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 8.5 (State corruption in critical transactions).
An authenticated user from `ORG-E8E3` can access or modify objects owned by `ORG-B111`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-E8E3`
- Response body `tenantId`: `ORG-B111` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/resources/RES-6461" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E8E3>"
```
Expected: Returns own record with `tenantId: "ORG-E8E3"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.claimsflow-unde.example.com/api/v1/resources/RES-7461" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E8E3>"
```
**Vulnerable:** Returns `tenantId: "ORG-B111"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 8.5
No specific variant documented for Pattern 8.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

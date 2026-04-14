# Expected Response

## System
- Domain: Education / EdTech LMS
- System: LearnPath Assessment Platform
- Example ID: BOLA-6615

## Priority Findings

### Finding 1: Confused deputy / brokerage failures (Pattern 4.1)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.1 (Confused deputy / brokerage failures).
An authenticated user from `ORG-E595` can access or modify objects owned by `ORG-7AF8`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-E595`
- Response body `tenantId`: `ORG-7AF8` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.learnpath-asses.example.com/api/v1/resources/RES-7615" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E595>"
```
Expected: Returns own record with `tenantId: "ORG-E595"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.learnpath-asses.example.com/api/v1/resources/RES-8615" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E595>"
```
**Vulnerable:** Returns `tenantId: "ORG-7AF8"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.1
No specific variant documented for Pattern 4.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Fitness / Wearables
- System: VitalTrack Health API
- Example ID: BOLA-6230

## Priority Findings

### Finding 1: Cache-key authorization mismatch (Pattern 1.11)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.11 (Cache-key authorization mismatch).
An authenticated user from `ORG-9C77` can access or modify objects owned by `ORG-D619`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-9C77`
- Response body `tenantId`: `ORG-D619` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v1/resources/RES-7230" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-9C77>"
```
Expected: Returns own record with `tenantId: "ORG-9C77"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v1/resources/RES-8230" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-9C77>"
```
**Vulnerable:** Returns `tenantId: "ORG-D619"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.11
No specific variant documented for Pattern 1.11 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

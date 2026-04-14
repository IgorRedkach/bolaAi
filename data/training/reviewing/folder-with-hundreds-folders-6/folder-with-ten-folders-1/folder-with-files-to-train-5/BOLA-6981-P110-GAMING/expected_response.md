# Expected Response

## System
- Domain: Gaming / MMO Backend
- System: RealmForge Game API
- Example ID: BOLA-6981

## Priority Findings

### Finding 1: Cross-service identity propagation drift (Pattern 1.10)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.10 (Cross-service identity propagation drift).
An authenticated user from `ORG-1B45` can access or modify objects owned by `ORG-AB6C`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-1B45`
- Response body `tenantId`: `ORG-AB6C` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.realmforge-game.example.com/api/v1/resources/RES-7981" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1B45>"
```
Expected: Returns own record with `tenantId: "ORG-1B45"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.realmforge-game.example.com/api/v1/resources/RES-8981" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-1B45>"
```
**Vulnerable:** Returns `tenantId: "ORG-AB6C"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.10
No specific variant documented for Pattern 1.10 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

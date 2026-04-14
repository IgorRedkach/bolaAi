# Expected Response

## System
- Domain: Fitness / Wearables
- System: VitalTrack Health API
- Example ID: BOLA-0931

## Priority Findings

### Finding 1: Default credentials and unnecessary services (Pattern 6.3)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.3 (Default credentials and unnecessary services).
An authenticated user from `ORG-48B9` can access or modify objects owned by `ORG-DD76`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-48B9`
- Response body `tenantId`: `ORG-DD76` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v1/resources/RES-1931" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-48B9>"
```
Expected: Returns own record with `tenantId: "ORG-48B9"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v1/resources/RES-2931" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-48B9>"
```
**Vulnerable:** Returns `tenantId: "ORG-DD76"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.3
No specific variant documented for Pattern 6.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

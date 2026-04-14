# Expected Response

## System
- Domain: Industrial IoT / Manufacturing
- System: ManuControl Robotics Fleet
- Example ID: BOLA-0157

## Priority Findings

### Finding 1: Resource exhaustion (DoS) (Pattern 8.4)
**Severity:** Critical
**Category:** Exceptional

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 8.4 (Resource exhaustion (DoS)).
An authenticated user from `ORG-B0F9` can access or modify objects owned by `ORG-0F7E`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-B0F9`
- Response body `tenantId`: `ORG-0F7E` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-1157" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B0F9>"
```
Expected: Returns own record with `tenantId: "ORG-B0F9"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-2157" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B0F9>"
```
**Vulnerable:** Returns `tenantId: "ORG-0F7E"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 8.4
No specific variant documented for Pattern 8.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

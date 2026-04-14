# Expected Response

## System
- Domain: Smart City / Traffic Management
- System: MetroPulse Traffic Orchestration
- Example ID: BOLA-0404

## Priority Findings

### Finding 1: Mass assignment via object fields (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.12 (Mass assignment via object fields).
An authenticated user from `ORG-D394` can access or modify objects owned by `ORG-3FC5`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D394`
- Response body `tenantId`: `ORG-3FC5` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.metropulse-traf.example.com/api/v1/resources/RES-1404" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D394>"
```
Expected: Returns own record with `tenantId: "ORG-D394"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.metropulse-traf.example.com/api/v1/resources/RES-2404" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D394>"
```
**Vulnerable:** Returns `tenantId: "ORG-3FC5"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.12
```bash
# Mass assignment
curl -s -X PATCH "/api/v1/resources/RES-2404" -H "Authorization: Bearer <TOKEN_TENANT_ORG-D394>" -d '{"ownerId":"attacker","tenantId":"ORG-D394"}'
# Vulnerable: ownership transferred
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

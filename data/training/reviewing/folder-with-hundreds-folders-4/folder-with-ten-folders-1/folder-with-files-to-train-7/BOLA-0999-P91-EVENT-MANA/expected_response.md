# Expected Response

## System
- Domain: Event Management / Ticketing
- System: VenueCore Ticketing API
- Example ID: BOLA-0999

## Priority Findings

### Finding 1: GraphQL: single endpoint vulnerabilities (Pattern 9.1)
**Severity:** Critical
**Category:** Platform

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 9.1 (GraphQL: single endpoint vulnerabilities).
An authenticated user from `ORG-55CA` can access or modify objects owned by `ORG-27F4`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-55CA`
- Response body `tenantId`: `ORG-27F4` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.venuecore-ticke.example.com/api/v1/resources/RES-1999" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-55CA>"
```
Expected: Returns own record with `tenantId: "ORG-55CA"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.venuecore-ticke.example.com/api/v1/resources/RES-2999" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-55CA>"
```
**Vulnerable:** Returns `tenantId: "ORG-27F4"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 9.1
No specific variant documented for Pattern 9.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

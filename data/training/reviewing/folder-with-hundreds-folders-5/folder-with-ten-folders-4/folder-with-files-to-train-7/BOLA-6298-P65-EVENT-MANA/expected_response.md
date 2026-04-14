# Expected Response

## System
- Domain: Event Management / Ticketing
- System: VenueCore Ticketing API
- Example ID: BOLA-6298

## Priority Findings

### Finding 1: Shadow AI and ungoverned ML endpoints (Pattern 6.5)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.5 (Shadow AI and ungoverned ML endpoints).
An authenticated user from `ORG-4A4F` can access or modify objects owned by `ORG-6949`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-4A4F`
- Response body `tenantId`: `ORG-6949` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.venuecore-ticke.example.com/api/v1/resources/RES-7298" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-4A4F>"
```
Expected: Returns own record with `tenantId: "ORG-4A4F"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.venuecore-ticke.example.com/api/v1/resources/RES-8298" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-4A4F>"
```
**Vulnerable:** Returns `tenantId: "ORG-6949"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.5
No specific variant documented for Pattern 6.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

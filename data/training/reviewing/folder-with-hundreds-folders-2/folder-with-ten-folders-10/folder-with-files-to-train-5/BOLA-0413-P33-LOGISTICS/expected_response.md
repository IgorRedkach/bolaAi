# Expected Response

## System
- Domain: Logistics / Supply Chain
- System: FreightLens Tracking API
- Example ID: BOLA-0413

## Priority Findings

### Finding 1: Semantic ambiguity (over-broad endpoints) (Pattern 3.3)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.3 (Semantic ambiguity (over-broad endpoints)).
An authenticated user from `ORG-F4E2` can access or modify objects owned by `ORG-D6CA`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-F4E2`
- Response body `tenantId`: `ORG-D6CA` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/resources/RES-1413" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F4E2>"
```
Expected: Returns own record with `tenantId: "ORG-F4E2"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.freightlens-tra.example.com/api/v1/resources/RES-2413" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F4E2>"
```
**Vulnerable:** Returns `tenantId: "ORG-D6CA"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.3
No specific variant documented for Pattern 3.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

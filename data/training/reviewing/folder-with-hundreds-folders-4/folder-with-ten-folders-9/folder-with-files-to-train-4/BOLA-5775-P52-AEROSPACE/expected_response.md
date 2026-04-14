# Expected Response

## System
- Domain: Aerospace / MRO
- System: WingTech Maintenance Portal
- Example ID: BOLA-5775

## Priority Findings

### Finding 1: Resolver/graph traversal injection (Pattern 5.2)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.2 (Resolver/graph traversal injection).
An authenticated user from `ORG-C867` can access or modify objects owned by `ORG-0349`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-C867`
- Response body `tenantId`: `ORG-0349` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/resources/RES-6775" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-C867>"
```
Expected: Returns own record with `tenantId: "ORG-C867"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/resources/RES-7775" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-C867>"
```
**Vulnerable:** Returns `tenantId: "ORG-0349"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.2
No specific variant documented for Pattern 5.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

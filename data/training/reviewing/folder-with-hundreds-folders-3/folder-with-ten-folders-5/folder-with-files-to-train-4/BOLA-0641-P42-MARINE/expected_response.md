# Expected Response

## System
- Domain: Marine / Port Logistics
- System: HarborFlow Port API
- Example ID: BOLA-0641

## Priority Findings

### Finding 1: Persistence poisoning via lifecycle actions (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.2 (Persistence poisoning via lifecycle actions).
An authenticated user from `ORG-EAC3` can access or modify objects owned by `ORG-BC8D`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-EAC3`
- Response body `tenantId`: `ORG-BC8D` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.harborflow-port.example.com/api/v1/resources/RES-1641" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-EAC3>"
```
Expected: Returns own record with `tenantId: "ORG-EAC3"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.harborflow-port.example.com/api/v1/resources/RES-2641" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-EAC3>"
```
**Vulnerable:** Returns `tenantId: "ORG-BC8D"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.2
No specific variant documented for Pattern 4.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

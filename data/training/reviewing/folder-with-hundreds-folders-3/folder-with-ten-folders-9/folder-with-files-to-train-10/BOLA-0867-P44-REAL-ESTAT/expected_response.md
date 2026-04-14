# Expected Response

## System
- Domain: Real Estate / PropTech
- System: EstateFlow Property API
- Example ID: BOLA-0867

## Priority Findings

### Finding 1: IaC state file exposure (Pattern 4.4)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.4 (IaC state file exposure).
An authenticated user from `ORG-F056` can access or modify objects owned by `ORG-A2C1`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-F056`
- Response body `tenantId`: `ORG-A2C1` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.estateflow-prop.example.com/api/v1/resources/RES-1867" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F056>"
```
Expected: Returns own record with `tenantId: "ORG-F056"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.estateflow-prop.example.com/api/v1/resources/RES-2867" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F056>"
```
**Vulnerable:** Returns `tenantId: "ORG-A2C1"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.4
No specific variant documented for Pattern 4.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

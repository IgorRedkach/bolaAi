# Expected Response

## System
- Domain: Marine / Port Logistics
- System: HarborFlow Port API
- Example ID: BOLA-0241

## Priority Findings

### Finding 1: Privilege escalation via parameter tampering (Pattern 2.4)
**Severity:** Critical
**Category:** BAC

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 2.4 (Privilege escalation via parameter tampering).
An authenticated user from `ORG-BC86` can access or modify objects owned by `ORG-ABEA`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-BC86`
- Response body `tenantId`: `ORG-ABEA` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.harborflow-port.example.com/api/v1/resources/RES-1241" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-BC86>"
```
Expected: Returns own record with `tenantId: "ORG-BC86"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.harborflow-port.example.com/api/v1/resources/RES-2241" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-BC86>"
```
**Vulnerable:** Returns `tenantId: "ORG-ABEA"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 2.4
No specific variant documented for Pattern 2.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

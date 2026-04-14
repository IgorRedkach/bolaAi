# Expected Response

## System
- Domain: Cybersecurity / SIEM
- System: ThreatLens SOC Platform
- Example ID: BOLA-6732

## Priority Findings

### Finding 1: SCADA and ICS (Pattern 9.4)
**Severity:** Critical
**Category:** Platform

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 9.4 (SCADA and ICS).
An authenticated user from `ORG-B82D` can access or modify objects owned by `ORG-507F`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-B82D`
- Response body `tenantId`: `ORG-507F` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.threatlens-soc-.example.com/api/v1/resources/RES-7732" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B82D>"
```
Expected: Returns own record with `tenantId: "ORG-B82D"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.threatlens-soc-.example.com/api/v1/resources/RES-8732" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B82D>"
```
**Vulnerable:** Returns `tenantId: "ORG-507F"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 9.4
No specific variant documented for Pattern 9.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

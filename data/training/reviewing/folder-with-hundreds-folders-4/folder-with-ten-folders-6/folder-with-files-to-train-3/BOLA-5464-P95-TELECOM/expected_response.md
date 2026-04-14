# Expected Response

## System
- Domain: Telecom / 5G Core
- System: SpectreNet Policy Control
- Example ID: BOLA-5464

## Priority Findings

### Finding 1: Smart Cities and IoT Networks (Pattern 9.5)
**Severity:** Critical
**Category:** Platform

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 9.5 (Smart Cities and IoT Networks).
An authenticated user from `ORG-7272` can access or modify objects owned by `ORG-A36C`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-7272`
- Response body `tenantId`: `ORG-A36C` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.spectrenet-poli.example.com/api/v1/resources/RES-6464" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7272>"
```
Expected: Returns own record with `tenantId: "ORG-7272"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.spectrenet-poli.example.com/api/v1/resources/RES-7464" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7272>"
```
**Vulnerable:** Returns `tenantId: "ORG-A36C"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 9.5
No specific variant documented for Pattern 9.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

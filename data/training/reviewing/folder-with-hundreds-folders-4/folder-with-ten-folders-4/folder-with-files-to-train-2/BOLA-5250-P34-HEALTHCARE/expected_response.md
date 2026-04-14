# Expected Response

## System
- Domain: Healthcare / EHR Platform
- System: PatientCore EHR API
- Example ID: BOLA-5250

## Priority Findings

### Finding 1: Implicit trust in callbacks (Pattern 3.4)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.4 (Implicit trust in callbacks).
An authenticated user from `ORG-EBBA` can access or modify objects owned by `ORG-4316`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-EBBA`
- Response body `tenantId`: `ORG-4316` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.patientcore-ehr.example.com/api/v1/resources/RES-6250" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-EBBA>"
```
Expected: Returns own record with `tenantId: "ORG-EBBA"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.patientcore-ehr.example.com/api/v1/resources/RES-7250" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-EBBA>"
```
**Vulnerable:** Returns `tenantId: "ORG-4316"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.4
No specific variant documented for Pattern 3.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

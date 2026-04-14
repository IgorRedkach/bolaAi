# Expected Response

## System
- Domain: Fitness / Wearables
- System: VitalTrack Health API
- Example ID: GQL-0131

## Priority Findings

### Finding 1: Fitness/Wearables — Parameter Escalation Exposes Cross-Tenant Health Metrics (Pattern 10.2)
**Severity:** High
**Category:** Single-User / Parameter Escalation / Own Session Scope Extension

**Summary:**
Per §5.0 (Pattern 10.2 — parameter escalation): The `getResource` resolver accepts `resourceId` without verifying that it belongs to the caller's tenant, enabling escalation beyond the caller's own session scope. An attacker from `tenant-e728` queried `getResource(id: "R-2131")` and received wearable health data belonging to `tenant-272e`, including `CONFIDENTIAL-e728272e`. In Fitness / Wearables, this exposes heart rate, sleep, activity, and biometric health data — sensitive personal health information.

**Evidence from HAR:**
- Request: `POST https://api.vitaltrack-health-ap.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e728`
- Query: `getResource(id: "R-2131") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-272e"`, `ownerId: "other-user-e728272e"`, `sensitiveField: "CONFIDENTIAL-e728272e"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e728272e`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.2 | Parameter escalation, own session scope |
| HAR request | x-tenant-id | Attacker tenant-e728 |
| HAR response | tenantId | Cross-tenant tenant-272e health data |
| HAR response | sensitiveField | CONFIDENTIAL-e728272e |

## Steps to Reproduce

### Step 1 — getResource with escalated resource ID (HAR)
```bash
curl -s -X POST https://api.vitaltrack-health-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e728" \
  -d '{"query": "query { getResource(id: \"R-2131\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-272e` biometric data returned. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Field-level access control: restrict health metrics to the owning user only.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.

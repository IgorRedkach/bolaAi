# Analysis Explanation
**Folder:** GQL-0259-HR-TECH | **Context source:** This folder's context.txt only.

## Step-by-step Analysis

### 1. Architecture (§2.0)
JobCore Candidate Portal, GraphQL at `https://api.jobcore-candidate-po.example.com/graphql`. Schema: `Candidate` type with `candidateId`, `listCandidates(tenantId: ID, status: String)`, `getCandidate(id: ID!)`.

### 2. Risk (§4.0)
RISK-GQL-259: `getCandidate` fetches by `candidateId` only; no tenancy check.

### 3. Pattern 6.1 — Schema Over-Exposure
The schema exposes a `tenantId` argument on `listCandidates` that clients can set arbitrarily. This over-exposes the relationship between tenants and their candidate data through the schema design itself.

### 4. HAR (§6.0)
- Endpoint: `api.jobcore-candidate-po.example.com`, JWT (standard), `x-tenant-id: tenant-0659`
- Request: `listCandidates(tenantId: "tenant-c4bb")` — attacker supplies victim tenant
- `x-request-id: req-0659c4bb` is a **response header** only
- HAR inconsistency: request is `listCandidates` but response key is `getCandidate` — documented as-is
- Response: `tenantId: tenant-c4bb`, `ownerId: other-user-0659c4bb`, `CONFIDENTIAL-0659c4bb`

**Consistency Guard:** system `JobCore Candidate Portal`, host `api.jobcore-candidate-po.example.com`, tenants `tenant-0659`/`tenant-c4bb`, `CONFIDENTIAL-0659c4bb`, RISK-GQL-259, Pattern 6.1 — from this folder's context.txt only.

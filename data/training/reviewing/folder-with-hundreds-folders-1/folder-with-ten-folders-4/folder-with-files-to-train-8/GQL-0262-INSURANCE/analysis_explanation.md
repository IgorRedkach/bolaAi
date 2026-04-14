# Analysis Explanation
**Folder:** GQL-0262-INSURANCE | **Context source:** This folder's context.txt only.

## Key Analysis Points

### Architecture
ClaimsFlow Underwriting API, GraphQL at `https://api.claimsflow-underwrit.example.com/graphql`. Schema: `Claim` type with `claimId`, `getClaim(id: ID!)`.

### Pattern 10.1 — ID Swap in Own Request
The attacker observes their own `claimId` value and swaps it with a victim's `C-2262` in the same request structure. The server processes this as if the caller had an authorized claim of that ID. No parameter change other than the ID is needed — the simplest single-user attack.

### HAR (§6.0)
- Host: `api.claimsflow-underwrit.example.com`, JWT, `x-tenant-id: tenant-6950`
- Request: `getClaim(id: "C-2262")` — straightforward ID swap
- `x-request-id: req-6950dd02` is a **response header** only
- Response key: `getClaim` — **consistent** with request operation (no inconsistency in this example)
- Response: `tenantId: tenant-dd02`, `ownerId: other-user-6950dd02`, `CONFIDENTIAL-6950dd02`, `internalNotes: Internal data exposed`
- RISK-GQL-262

### Insurance Domain Impact
Claim records contain accident reconstruction data, medical treatment records, and claimant financial data. Cross-tenant access by a competitor insurer or fraudulent claimant constitutes both a regulatory breach and potential insurance fraud enablement.

**Consistency Guard:** system `ClaimsFlow Underwriting API`, host `api.claimsflow-underwrit.example.com`, tenants `tenant-6950`/`tenant-dd02`, claim ID `C-2262`, `ownerId: other-user-6950dd02`, `CONFIDENTIAL-6950dd02`, RISK-GQL-262, Pattern 10.1 — from this folder's context.txt only.

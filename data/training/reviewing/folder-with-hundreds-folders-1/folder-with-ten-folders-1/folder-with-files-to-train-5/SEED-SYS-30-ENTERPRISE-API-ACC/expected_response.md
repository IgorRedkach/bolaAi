## System

- System: IdentityVault Enterprise Customer API v5.0.0
- Domain: ENTERPRISE SAAS / IDENTITY & ACCESS MANAGEMENT (IAM)
- Risk ID: RISK-GRPH-904

## Findings

### 1. GraphQL Alias Batching Rate-Limit Bypass — 5,000 Parallel Resolver Calls in a Single HTTP Request (Pattern 9.1)

The Go-lang API Gateway enforces a rate limit of 10 HTTP requests/second. The GraphQL resolver engine executes each aliased field in the query as a separate internal database lookup. An attacker submits a single POST `/graphql` request with 5,000 aliased `user()` fields (`u1`, `u2`, ... `u5000`), each targeting a different sequential user ID. The gateway permits the single request; the resolver engine processes all 5,000 lookups within the same HTTP transaction.

**HAR evidence**: single POST `https://api.identityvault.com/graphql`, body size 200,000 bytes, contains 5,000 aliases. Response: HTTP 200 OK. Response header `x-resolver-nodes-processed: 5000` confirms all 5,000 sub-queries executed. Request time: 712ms — consistent with 5,000 sequential DB lookups. Rate limit (10 req/s) was not triggered.

### 2. Metadata Side-Channel — Soft Authorization Failure Leaks Existence of Cross-Tenant User IDs (Pattern 2.2)

The resolver (`userResolver.js`, section 6.1) returns `null` both for non-existent user IDs and for existing-but-unauthorized users:

```javascript
const user = await User.findById(id);
if (!user) {
    return null;  // Returns null for truly non-existent IDs
}
if (user.tenantId !== authTenantId) {
    return null;  // FLAW: Leaks existence metadata to the attacker
}
return user;
```

Both cases return `null` in the resolver, but the code performs `User.findById(id)` before the BOLA check — meaning for unauthorized-but-existing users, the resolver performs a full DB read. Section 3.2 documents the flaw: "if the BOLA check fails, the resolver returns an empty payload or `null` instead of a hard error." For non-existent IDs, the DB read is faster (empty result); for unauthorized-existing IDs, the DB read completes and the object is silently discarded but `null` is returned. The attacker distinguishes existing cross-tenant users by response content (non-null objects appear for IDs where the BOLA check failed to block the response).

**HAR evidence**: response contains mixed `null` and populated objects. `u3` returns `{"email": "cfo.smith@competitor-corp.com", "tenantId": "COMPETITOR_TENANT_001"}` and `u105` returns `{"email": "hr.lead@other-enterprise.com", "tenantId": "ENTERPRISE_B_889"}` — actual cross-tenant user data exposed to PARTNER-A, confirming the BOLA check did not prevent data exposure (not just existence leakage, but full object exposure for some IDs).

### 3. Cross-Tenant User Data Exposure — BOLA via Sequential ID Enumeration (Pattern 1.5)

The response from a single request exposes email addresses and `tenantId` values belonging to `COMPETITOR_TENANT_001` and `ENTERPRISE_B_889`. The user IDs are sequentially guessable (section 4.0: "UUIDv4 generation that is temporally ordered"). The `user_profiles` schema isolates tenants via `tenant_id NOT NULL` (section 5.0), but the resolver returns full objects for IDs where the BOLA check was not triggered or failed — exposing corporate email addresses of competitor employees.

## Evidence

- **HAR trace**: single 200KB request; `x-resolver-nodes-processed: 5000`; non-null entries include cross-tenant email and `tenantId` data — competitor emails confirmed in response body.
- **Resolver code** (section 6.1): `User.findById(id)` executed before BOLA check; `return null` on BOLA failure leaks existence; populated object returned for some cross-tenant IDs (BOLA check failure confirmed by response).
- **Schema** (section 5.0): `tenant_id NOT NULL` — isolation contract exists; resolver does not enforce it consistently.
- **Architecture** (section 3.2): RISK-GRPH-904 documents the soft-fail behavior; section 4.0 documents sequentially guessable IDs and alias batching surface.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.identityvault.com
Authorization: Bearer <PARTNER_A_JWT>
Content-Type: application/json

{"query": "query MassUserEnumeration { u1: user(id: \"usr-000001\") { email tenantId } u2: user(id: \"usr-000002\") { email tenantId } ... u5000: user(id: \"usr-050000\") { email tenantId } }"}
```

Expected secure outcome: HTTP 429 — alias depth limit exceeded (max 10 aliases per request); or each cross-tenant alias returns a hard GraphQL error, not `null`.  
Observed vulnerable outcome: HTTP 200 OK, `x-resolver-nodes-processed: 5000`, response contains cross-tenant user records in populated alias fields.

## Remediation

- **Enforce a GraphQL alias/query depth limit** (RISK-GRPH-904): reject queries with more than a configurable maximum number of aliases (e.g., 10–50). This prevents the O(n) DB hit inside a single HTTP request and restores HTTP-level rate limit effectiveness.
- **Return a hard GraphQL error on BOLA failure, not `null`**: throw `new ForbiddenError("Access denied")` when `user.tenantId !== authTenantId` instead of `return null`. This prevents the soft-fail side channel that leaks existence metadata.
- **Apply `tenant_id` filter in the database query**: replace `User.findById(id)` with `User.findOne({ user_id: id, tenant_id: authTenantId })` — the DB returns nothing for cross-tenant IDs, eliminating the need for an application-level BOLA check.
- **Use opaque, non-sequential user IDs**: replace the temporally-ordered UUID variant with a fully random UUIDv4 to prevent sequential enumeration.

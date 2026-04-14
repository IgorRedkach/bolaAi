## Analysis reasoning

I reviewed the IdentityVault Enterprise Customer API v5.0.0 architecture specification, Node.js resolver code, schema, and HAR trace.

1. **Rate-limit bypass via alias batching**: the Go-lang API Gateway rate limit applies at the HTTP request level (10 req/s). GraphQL aliases allow multiple logical resolver calls within a single HTTP request. The HAR body is 200,000 bytes — the full query contains 5,000 aliased `user()` fields. The response header `x-resolver-nodes-processed: 5000` is direct evidence that 5,000 DB lookups executed. One HTTP request. The rate limiter counted 1 against its 10-req/s window.

2. **Soft-fail side channel AND full object exposure**: section 3.2 describes the soft-fail behavior (null vs. 403). The HAR response goes further — it contains actual populated objects (`u3: {email: "cfo.smith@competitor-corp.com", tenantId: "COMPETITOR_TENANT_001"}`). This is not just existence leakage; it is full BOLA data exposure for some IDs. The resolver code's path explains this: `User.findById(id)` returns the user; then `if (user.tenantId !== authTenantId) { return null }` is supposed to block it. But the HAR shows populated data in the response for cross-tenant IDs — meaning the BOLA check was not consistently applied (possibly a code path where the check is skipped, or the HAR represents the expected failure mode when the check returns `null` for non-existent IDs while full data flows for some IDs where the check path differs).

3. **Sequential ID pattern enables targeted enumeration**: section 4.0 notes the UUIDs are "temporally ordered" — meaning IDs generated at similar times share a timestamp-derived prefix. An attacker who owns one account can derive adjacent IDs for other accounts created around the same time. This transforms the alias attack from random shotgun enumeration into targeted time-window enumeration.

4. **Schema isolation exists but is not enforced**: the `user_profiles` table has `tenant_id NOT NULL` and an index on `(tenant_id)`. The proper fix is to push the tenant filter to the SQL `WHERE` clause — `WHERE user_id = $1 AND tenant_id = $2`. The current resolver performs a full fetch then a post-read check, which is both less efficient and exploitable via the soft-fail side channel.

5. **Impact classification**: the HAR response includes corporate email addresses of CFO and HR Lead of competitor organizations. This is a direct competitive intelligence breach — cross-tenant PII exposure in an enterprise IAM context. Each non-null alias result maps to one validated corporate email + tenant identity.

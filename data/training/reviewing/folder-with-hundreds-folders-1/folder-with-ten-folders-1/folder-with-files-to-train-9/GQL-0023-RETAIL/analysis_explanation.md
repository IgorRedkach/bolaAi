## Analysis reasoning

1. **HAR shows `updateResource` write as primary**: HAR is `updateResource(id: "R-2023", input: {status: "approved"...})`. The original expected_response.md started with `getResource` which does not match the HAR.

2. **Pattern 1.1 applies to ALL resolvers that use the same unguarded ID argument**: section 5.0 describes the flaw as "resolver accepts `resourceId` from the query without verifying ownership." This means not just `getResource` but also `updateResource` and `deleteResource` — all share the same missing ownership check. The HAR demonstrates this through the write path, which is more impactful than a read.

3. **Loyalty programme context — reward fraud**: `status: "approved"` on a loyalty reward record in a points ledger system is a business-critical state transition. Approving another retailer's pending redemption without authorization constitutes fraud — triggering unauthorized points disbursement from the victim retailer's loyalty balance.

4. **Bulk lookup is confirmed, not conditional**: section 4.0 documents the gap.

5. **Introspection removed**: not documented in sections 4.0 or 5.0.

6. **Redis cache added**: section 2.0 documents `resourceId`-only cache key.

7. **HAR response/request mismatch**: request is `updateResource` mutation but response is `getResource`. Same synthetic artifact. Confirmed signal: `tenantId: tenant-576a` with HTTP 200.

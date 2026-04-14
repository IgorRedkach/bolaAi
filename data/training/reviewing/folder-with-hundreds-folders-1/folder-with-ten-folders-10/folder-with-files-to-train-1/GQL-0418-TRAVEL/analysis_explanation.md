## Analysis reasoning

1. **HAR shows `updateResource` write as primary**: HAR is `updateResource(id: "R-2418", input: {status: "approved"...})`. Original expected_response.md used `getResource` single-ID.

2. **Pattern 10.5 (Draft/Non-Published) must show the discovery + promotion chain**: discovery via `listResources(status: "draft")`, then promotion via `updateResource(status: "approved")`. This is the full Pattern 10.5 attack sequence.

3. **Travel/GDS context for draft resources**: in a GDS, draft resources may be unpublished fare rules, pending inventory configurations, or unreleased booking policies. Approving these prematurely creates business harm — revealing pre-launch pricing, disrupting release schedules, or activating unvetted booking rules.

4. **Bulk lookup confirmed**: section 4.0 documents the gap.

5. **Introspection removed**: not documented in sections 4.0 or 5.0.

6. **HAR response/request mismatch**: request is `updateResource` but response is `getResource`. Same synthetic artifact. Confirmed signal: `tenantId: tenant-74b8` with HTTP 200.

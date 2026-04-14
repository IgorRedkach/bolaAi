## Analysis reasoning

1. **HAR shows `bulkResourceLookup` batch as primary**: HAR is `bulkResourceLookup(ids: ["R-2021", "R-1021", "R-3021"])`. The original expected_response.md used `getResource` single-ID as primary — wrong.

2. **Pattern 10.2 (Parameter Escalation) distinctive mechanism**: the attacker doesn't need to issue a separate unauthorized request. They include their own valid ID (`R-1021`) alongside foreign IDs in the same list — extending the scope of a single authorized session beyond its allowed boundary. The server treats the entire list as a single operation, returning all results without per-element authorization. This is the "own session scope extension" aspect: the session is legitimately authenticated, but the parameter value extends what that session can access.

3. **Pharmaceutical/21 CFR Part 11 context makes bulk access particularly dangerous**: in a clinical trials system, a single `bulkResourceLookup` call could expose an entire competing pharma company's trial protocol cohort, adverse event reports, or interim efficacy data — proprietary research that took years and hundreds of millions to generate. This is industrial espionage in a regulated environment.

4. **`auditLog` field access via cross-tenant bulk is a secondary concern**: reading another company's `auditLog` for trial records exposes who accessed which data and when — revealing their internal researchers and access patterns.

5. **Bulk lookup is the primary documented attack**: section 4.0 confirms `bulkResourceLookup` lacks per-ID ownership filtering.

6. **Introspection removed**: not documented in sections 4.0 or 5.0.

7. **Redis cache added**: section 2.0 documents `resourceId`-only cache key.

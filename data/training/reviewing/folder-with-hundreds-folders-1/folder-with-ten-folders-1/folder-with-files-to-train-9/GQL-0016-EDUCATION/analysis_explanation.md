## Analysis reasoning

1. **HAR matches `getResource` single-ID read**: HAR is `getResource(id: "R-2016")` from `tenant-f900` returning `tenant-5d44` — kept as primary step.

2. **Pattern 5.2 (Resolver/Graph Traversal) requires the `getResourceWithChildren` step**: the pattern description in section 5.0 is explicit — "resolver chain follows nested relationships without re-validating authorization at each level." The `getResourceWithChildren` query is the canonical Pattern 5.2 exploit: use an authorized root query entry point, inject a cross-tenant `resourceId`, and traverse the graph to retrieve all nested `items` without any per-level auth check. The original expected_response.md showed only the flat `getResource` call and never demonstrated the traversal aspect.

3. **EdTech context makes traversal especially impactful**: in an assessment platform, `Item` objects are the most sensitive records — exam questions, answer keys, and student submissions. Reading these via traversal (rather than direct access) bypasses any direct access controls that might exist on `getItem` while exploiting the trust the resolver places in the authorized parent context.

4. **Distinction between Pattern 1.1 (direct ID substitution) and Pattern 5.2 (traversal)**: Pattern 1.1 is a flat `getResource(id: cross-tenant-id)` call. Pattern 5.2 specifically uses graph traversal — the attacker starts from an authorized or cross-tenant parent and reads related children without separate authorization at the child resolver level.

5. **Bulk lookup confirmed, not conditional**: section 4.0 explicitly documents `bulkResourceLookup` lacking per-ID filter.

6. **Introspection removed**: not documented in sections 4.0 or 5.0.

7. **Redis cache added**: section 2.0 documents `resourceId`-only cache key.

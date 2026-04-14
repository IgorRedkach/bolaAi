## Analysis reasoning

1. **This is the one example where the introspection step IS the primary finding**: section 5.0 explicitly states "GraphQL introspection is enabled in production. The schema exposes internal type names, field descriptions, and sensitive relationship paths that aid exploitation." This is Pattern 6.1 (Schema/relationship over-exposure). In all previous examples, introspection was a speculative step not grounded in the context. Here it is the documented primary vulnerability.

2. **Introspection enables and amplifies all subsequent BOLA attacks**: by exposing `sensitiveField`, `internalNotes`, `auditLog`, and `items` relationship paths, introspection transforms a partial data access into a complete extraction attack. The original expected_response.md treated introspection as Step 4 ("if Pattern 6.1 also present") — it should be Step 1 as the documented primary attack, with the BOLA attacks following as the exploitation that introspection enables.

3. **HAR shows `listResources` tenant override as the secondary BOLA**: HAR request is `listResources(tenantId: "tenant-6cab")` from `tenant-2d4e`. The original expected_response.md started with `getResource` single-ID which doesn't match the HAR. The `listResources` tenant override should be Step 2 — the BOLA attack that introspection discovery enables.

4. **Attack chain is the key training signal**: introspection → discover field names → craft targeted query → extract data. This two-phase attack is specifically what Pattern 6.1 describes.

5. **Bulk lookup confirmed, not conditional**: section 4.0 documents `bulkResourceLookup` lacking per-ID ownership filtering.

6. **Redis cache added**: section 2.0 documents `resourceId`-only cache key.

## Analysis reasoning

1. **HAR matches `getResource` single-ID substitution**: correct primary step. Pattern 10.2 emphasis: single-session scope extension via parameter value change.

2. **Bulk lookup confirmed, not conditional**: section 4.0 documents `bulkResourceLookup` lacking per-ID filter.

3. **Introspection removed**: not documented in sections 4.0 or 5.0.

4. **Redis cache added**: section 2.0 documents `resourceId`-only cache key.

5. **Real estate impact**: property listing data including buyer qualification and negotiation notes is commercially sensitive. One ID change grants access to a competing agency's entire deal pipeline.

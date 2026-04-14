## Analysis reasoning

1. **HAR shows `getResource` single-ID as HAR primary, but Pattern 1.3 (Bulk/List) should be the primary finding**: section 5.0 is explicit — Pattern 1.3 is specifically about the `listResources` bulk/list endpoint. The original expected_response.md never demonstrated the `listResources` attack at all, which is the defining characteristic of Pattern 1.3. The HAR single-ID read is a secondary finding (RISK-GQL-025).

2. **Pattern 1.3 has two sub-attacks**: (a) omit `tenantId` entirely — gets ALL data; (b) supply a different `tenantId` — gets a specific tenant's data. Both are documented in section 5.0 ("filter is omitted OR supplied from client without JWT-level validation"). The training signal must demonstrate both.

3. **Mining fleet context amplifies bulk list impact**: unlike a single-record read, `listResources` returning all tenants' data exposes a competitor mining company's entire fleet inventory, including real-time GPS positions (`items: [Item!]` as telemetry), vehicle maintenance status, and ore extraction schedules. This enables targeted competitive intelligence or physical asset interference.

4. **Bulk lookup is confirmed**: section 4.0 documents `bulkResourceLookup` lacking per-ID filter.

5. **Introspection removed**: not documented in sections 4.0 or 5.0.

6. **Redis cache with fleet telemetry**: real-time fleet position data cached without tenant dimension could serve competitor mining operators with live GPS coordinates of another company's vehicles.

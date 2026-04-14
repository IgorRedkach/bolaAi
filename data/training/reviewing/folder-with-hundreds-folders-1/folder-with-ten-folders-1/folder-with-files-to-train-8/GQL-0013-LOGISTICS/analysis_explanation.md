## Analysis reasoning

1. **HAR matches `getShipment` single-ID substitution**: HAR is `getShipment(id: "S-2013")` from `tenant-de82` returning `tenant-c094` — kept as primary step.

2. **Pattern 3.3 (Semantic Ambiguity) requires more than a single read step**: the pattern specifically calls out "over-broad endpoints" — endpoints that are designed to be wide query surfaces without semantic tenancy constraints. Three endpoints in the schema exhibit this: `getShipment`, `listShipments`, and `getShipmentWithChildren`. The original expected_response.md showed only the single-ID read and didn't address the semantic ambiguity across all three endpoints or the additional exploitation path via `getShipmentWithChildren` loading the full nested graph.

3. **`getShipmentWithChildren` amplifies the data exposure**: loading `waypoints` (GPS sequence, lat/lng, ETA) reveals full real-time route and delivery schedule for any tenant's shipments. In logistics, this is extremely sensitive competitive intelligence.

4. **Bulk lookup confirmed, not conditional**: section 4.0 documents `bulkShipmentLookup` lacking per-ID filter.

5. **Introspection removed**: not documented in sections 4.0 or 5.0.

6. **Redis cache added**: section 2.0 documents `shipmentId`-only cache key. Cached shipment GPS and route data without a tenant dimension would allow cross-tenant access to bypass any server-side auth.

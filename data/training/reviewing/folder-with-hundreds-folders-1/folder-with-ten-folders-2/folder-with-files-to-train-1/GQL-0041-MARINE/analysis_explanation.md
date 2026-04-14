# Analysis Explanation

**System analysed:** HarborFlow Port API — GQL-0041 (Marine / Port Logistics)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 9.1 (GraphQL single-endpoint vulnerabilities). "The GraphQL single-endpoint pattern means all operations (including sensitive mutations) are accessible at one URL. Per-operation authorization is missing for write operations."
2. **Read Section 3.0 schema** — Note domain-specific types: `Shipment`, `shipmentId`, `waypoints`, `bulkShipmentLookup`. `updateShipment` and `bulkShipmentLookup` are at the same endpoint as queries.
3. **Read Section 4.0** — RISK-GQL-041: resolver does not verify `tenantId`. `bulkShipmentLookup` has no per-ID filter.
4. **Read Section 2.0** — Redis cache keyed by `shipmentId` only.
5. **Read HAR** — Attack is a WRITE mutation: `updateShipment(id: "S-2041", input: {status: "approved", ownerId: "attacker-3237ad04"})`. Attacker `tenant-3237` targeted `tenant-ad04`. Response `200 OK` returned `tenant-ad04` data: `CONFIDENTIAL-3237ad04`, `internalNotes: "Internal data exposed"`. `x-request-id: req-3237ad04`.
6. **Pattern 9.1 interpretation** — The single `/graphql` endpoint means the write mutation (`updateShipment`) shares a URL with reads. No per-operation WAF/gateway distinction. The per-operation authorization gap (§5.0) is confirmed by the successful cross-tenant write in the HAR.
7. **ownerId injection** — `ownerId: "attacker-3237ad04"` in the mutation input demonstrates mass assignment on top of the BOLA — same pattern as GQL-0037 but in marine/logistics domain with different types.

## Consistency Guard
- All tenant IDs (`tenant-3237`, `tenant-ad04`), shipment IDs (`S-2041`), injected ownerId (`attacker-3237ad04`), leaked values (`CONFIDENTIAL-3237ad04`, `other-user-3237ad04`), request IDs (`req-3237ad04`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.

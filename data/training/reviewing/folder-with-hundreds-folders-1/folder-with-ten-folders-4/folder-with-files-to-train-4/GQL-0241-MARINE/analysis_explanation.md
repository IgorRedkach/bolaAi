# Analysis Explanation
**System analysed:** HarborFlow Port API — GQL-0241 (Marine / Port Logistics)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-241: `bulkShipmentLookup` resolver lacks per-ID `tenantId` ownership check.
2. §5.0 Pattern 10.2: Single-User — parameter escalation/session scope extension; attacker passes victim's shipment IDs in bulk lookup to extend their session scope.
3. HAR: `tenant-be22` calls `bulkShipmentLookup(ids: ["S-2241","S-1241","S-3241"])` → `tenant-6ee0` shipment data: `CONFIDENTIAL-be226ee0`, `req-be226ee0`.
4. Marine/Port Logistics domain: cargo manifests, vessel assignments, customs docs — ISPS Code compliance required.

## Consistency Guard
Attacker: `tenant-be22`. Victim: `tenant-6ee0`. Shipments: `S-2241`, `S-1241`, `S-3241`. Sensitive: `CONFIDENTIAL-be226ee0`. ownerId: `other-user-be226ee0`. Request: `req-be226ee0`. All from this folder only.

# Analysis Explanation
**System analysed:** FreightLens Tracking API — GQL-0213 (Logistics / Freight Tracking)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-213: `getShipment` resolver fetches by `shipmentId` only, no `tenantId` ownership check.
2. §5.0 Pattern 5.1: Injection — authorization-bypass injection; `ownerId` in mutation input bypasses JWT ownership check.
3. HAR: `tenant-0d9b` submits `updateShipment(id: "S-2213", input: {ownerId: "attacker-0d9b4cd5"})` → `tenant-4cd5` shipment: `CONFIDENTIAL-0d9b4cd5`, `req-0d9b4cd5`.
4. Logistics domain: cargo manifests, route data, customs records — cargo theft and customs fraud.

## Consistency Guard
Attacker: `tenant-0d9b`. Victim: `tenant-4cd5`. Shipment: `S-2213`. Sensitive: `CONFIDENTIAL-0d9b4cd5`. ownerId input: `attacker-0d9b4cd5`. Request: `req-0d9b4cd5`. All from this folder only.

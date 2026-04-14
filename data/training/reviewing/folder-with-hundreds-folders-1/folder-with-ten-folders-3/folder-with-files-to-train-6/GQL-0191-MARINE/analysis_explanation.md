# Analysis Explanation
**System analysed:** HarborFlow Port API — GQL-0191 (Marine / Port Operations)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-191: `getResource`/`listShipments` resolver lacks `tenantId` ownership check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 5.1: Injection — authorization-bypass injection via `tenantId` argument injected into resolver logic.
3. HAR: `tenant-804f` queries `listShipments(tenantId: "tenant-06b0")` → `tenant-06b0` shipment records: `CONFIDENTIAL-804f06b0`, `req-804f06b0`.
4. Marine domain: cargo manifests, vessel schedules, customs declarations — national security and trade compliance risk.

## Consistency Guard
Attacker: `tenant-804f`. Victim: `tenant-06b0`. Shipment: `S-2191`. Sensitive: `CONFIDENTIAL-804f06b0`. ownerId: `other-user-804f06b0`. Request: `req-804f06b0`. All from this folder only.

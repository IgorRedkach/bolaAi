# Analysis Explanation
**System analysed:** PowerGrid Customer Billing API — GQL-0214 (Energy / Smart Grid Billing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-214: `getMeter` resolver fetches by `meterId` only, no `tenantId` ownership check.
2. §5.0 Pattern 5.2: Injection — resolver/graph traversal injection; cross-tenant `meterId` triggers unauthorized billing data traversal.
3. HAR: `tenant-c4c8` queries `getMeter(id: "M-2214")` → `tenant-df9a` meter billing data: `CONFIDENTIAL-c4c8df9a`, `req-c4c8df9a`.
4. Energy domain: meter readings, tariff data, consumption patterns — billing fraud and infrastructure mapping.

## Consistency Guard
Attacker: `tenant-c4c8`. Victim: `tenant-df9a`. Meter: `M-2214`. Sensitive: `CONFIDENTIAL-c4c8df9a`. ownerId: `other-user-c4c8df9a`. Request: `req-c4c8df9a`. All from this folder only.

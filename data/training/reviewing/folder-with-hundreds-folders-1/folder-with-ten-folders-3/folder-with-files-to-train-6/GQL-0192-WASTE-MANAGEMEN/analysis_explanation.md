# Analysis Explanation
**System analysed:** CleanRoute IoT Platform — GQL-0192 (Waste Management / IoT Fleet)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-192: `getResource`/`listResources` resolver lacks `tenantId` ownership check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 5.2: Injection — resolver/graph traversal injection; `tenantId` argument triggers unauthorized graph traversal.
3. HAR: `tenant-fe4a` queries `listResources(tenantId: "tenant-02c6")` → `tenant-02c6` IoT fleet records: `CONFIDENTIAL-fe4a02c6`, `req-fe4a02c6`.
4. Waste Management IoT domain: route data, vehicle telemetry, sensor readings — operational interference and infrastructure mapping.

## Consistency Guard
Attacker: `tenant-fe4a`. Victim: `tenant-02c6`. Resource: `R-2192`. Sensitive: `CONFIDENTIAL-fe4a02c6`. ownerId: `other-user-fe4a02c6`. Request: `req-fe4a02c6`. All from this folder only.

# Analysis Explanation
**System analysed:** SpectreNet Policy Control — GQL-0115 (Telecom / 5G Core)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.6: `bulkResourceLookup` accepts arbitrary IDs without ownership check; write-path exposure.
2. HAR: `tenant-1eab` queries `R-2115, R-1115, R-3115` → `tenant-af55` data: `CONFIDENTIAL-1eabaf55`, `req-1eabaf55`.
3. Telecom/5G: subscriber QoS rules, network slice config — critical telecom infrastructure.

## Consistency Guard
Attacker: `tenant-1eab`. Victim: `tenant-af55`. Resources: `R-2115, R-1115, R-3115`. Sensitive: `CONFIDENTIAL-1eabaf55`. ownerId: `other-user-1eabaf55`. Request: `req-1eabaf55`. All from this folder only.

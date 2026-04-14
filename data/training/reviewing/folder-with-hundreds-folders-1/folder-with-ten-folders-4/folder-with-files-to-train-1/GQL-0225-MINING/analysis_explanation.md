# Analysis Explanation
**System analysed:** OreTrack Fleet Management — GQL-0225 (Mining / Resource Extraction)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-225: `getResource`/`bulkResourceLookup` resolver lacks `tenantId` ownership check.
2. §5.0 Pattern 1.6: BOLA — write operations without ownership check; bulk lookup returns cross-tenant fleet data.
3. HAR: `tenant-7f27` queries `bulkResourceLookup(ids: ["R-2225", "R-1225", "R-3225"])` → `tenant-ed9f` fleet data: `CONFIDENTIAL-7f27ed9f`, `req-7f27ed9f`.
4. Mining domain: fleet telemetry, equipment schedules, operational data — industrial espionage.

## Consistency Guard
Attacker: `tenant-7f27`. Victim: `tenant-ed9f`. Resource: `R-2225`. Sensitive: `CONFIDENTIAL-7f27ed9f`. ownerId: `other-user-7f27ed9f`. Request: `req-7f27ed9f`. All from this folder only.

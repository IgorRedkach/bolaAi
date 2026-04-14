# Analysis Explanation
**System analysed:** SkyPort Global Distribution — GQL-0218 (Travel / Global Distribution)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-218: `getResource`/`bulkResourceLookup` resolver lacks `tenantId` check.
2. §5.0 Pattern 10.1: Single-User — ID swap in own bulk request bypasses ownership checks.
3. HAR: `tenant-8af0` queries `bulkResourceLookup(ids: ["R-2218", "R-1218", "R-3218"])` → `tenant-4ebb` booking data: `CONFIDENTIAL-8af04ebb`, `req-8af04ebb`.
4. Travel domain: booking records, passenger data, fare configurations — PII exposure and travel fraud.

## Consistency Guard
Attacker: `tenant-8af0`. Victim: `tenant-4ebb`. Resource: `R-2218`. Sensitive: `CONFIDENTIAL-8af04ebb`. ownerId: `other-user-8af04ebb`. Request: `req-8af04ebb`. All from this folder only.

# Analysis Explanation
**System analysed:** SkyPort Global Distribution — GQL-0168 (Travel / GDS)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 4.2: `bulkResourceLookup` — persistence poisoning via booking lifecycle.
2. HAR: `tenant-31f1` queries `R-2168, R-1168, R-3168` → `tenant-60b5`: `CONFIDENTIAL-31f160b5`, `req-31f160b5`.
3. Travel/GDS: passenger PII, pricing agreements, loyalty data.

## Consistency Guard
Attacker: `tenant-31f1`. Victim: `tenant-60b5`. Resources: `R-2168, R-1168, R-3168`. Sensitive: `CONFIDENTIAL-31f160b5`. ownerId: `other-user-31f160b5`. Request: `req-31f160b5`. All from this folder only.

# Analysis Explanation
**System analysed:** JobCore Candidate Portal — GQL-0159 (HR Tech / Talent Acquisition)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.6: `listCandidates` accepts client `tenantId` — write BOLA.
2. HAR: `tenant-d4f2` passes `tenantId: "tenant-daf6"` → `CONFIDENTIAL-d4f2daf6`, `req-d4f2daf6`.
3. HR Tech: candidate PII, compensation expectations — privacy and recruitment IP.

## Consistency Guard
Attacker: `tenant-d4f2`. Victim: `tenant-daf6`. Sensitive: `CONFIDENTIAL-d4f2daf6`. ownerId: `other-user-d4f2daf6`. Request: `req-d4f2daf6`. All from this folder only.

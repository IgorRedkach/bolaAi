# Analysis Explanation
**System analysed:** JobCore Candidate Portal — GQL-0109 (HR Tech / Talent Acquisition)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-109: `bulkCandidateLookup` accepts arbitrary IDs, enabling Pattern 10.2 (parameter escalation).
2. HAR: `tenant-06ed` queries `C-2109, C-1109, C-3109` → returns `tenant-f473` data: `CONFIDENTIAL-06edf473`, `req-06edf473`.
3. HR Tech: candidate PII (compensation, interview notes) — confidential employment data.

## Consistency Guard
Attacker: `tenant-06ed`. Victim: `tenant-f473`. Resources: `C-2109, C-1109, C-3109`. Sensitive: `CONFIDENTIAL-06edf473`. Request: `req-06edf473`. All from this folder only.

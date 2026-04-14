# Analysis Explanation
**System analysed:** JobCore Candidate Portal — GQL-0209 (HR Tech / Talent Acquisition)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-209: `getCandidate` resolver fetches by `candidateId` only, no `tenantId` ownership check.
2. §5.0 Pattern 2.2: BAC — metadata/attribute side-channel; mutation response leaks cross-tenant candidate attributes.
3. HAR: `tenant-dd84` submits `updateCandidate(id: "C-2209", input: {ownerId: "attacker-dd84c95f"})` → `tenant-c95f` candidate record: `CONFIDENTIAL-dd84c95f`, `req-dd84c95f`.
4. HR Tech domain: candidate profiles, assessment data, salary expectations — GDPR/employment privacy violation.

## Consistency Guard
Attacker: `tenant-dd84`. Victim: `tenant-c95f`. Candidate: `C-2209`. Sensitive: `CONFIDENTIAL-dd84c95f`. ownerId input: `attacker-dd84c95f`. Request: `req-dd84c95f`. All from this folder only.

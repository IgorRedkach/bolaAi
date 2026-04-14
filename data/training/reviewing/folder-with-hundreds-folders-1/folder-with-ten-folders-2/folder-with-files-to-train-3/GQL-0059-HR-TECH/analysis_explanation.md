# Analysis Explanation
**System analysed:** JobCore Candidate Portal — GQL-0059 (HR Tech / Talent Acquisition)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 5.1 (authorization-bypass injection). `candidateId` resolver lacks ownership enforcement; `CandidateInput` accepts `ownerId` enabling injection.
2. Domain types: `Candidate`, `candidateId`, `updateCandidate` (from HAR).
3. HAR: `updateCandidate(id: "C-2059", input: {status: "approved", ownerId: "attacker-2eec14dc"})`. Response `tenant-14dc`: `CONFIDENTIAL-2eec14dc`. `x-request-id: req-2eec14dc`.

## Consistency Guard
Tenant IDs: `tenant-2eec`, `tenant-14dc`. Candidate: `C-2059`. Injected ownerId: `attacker-2eec14dc`. Leaked: `CONFIDENTIAL-2eec14dc`, `other-user-2eec14dc`. Request: `req-2eec14dc`. All from this folder only.

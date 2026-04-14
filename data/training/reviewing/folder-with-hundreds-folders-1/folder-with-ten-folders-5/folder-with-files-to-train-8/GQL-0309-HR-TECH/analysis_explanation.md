# Analysis Explanation
**Folder:** GQL-0309-HR-TECH | **Context source:** This folder's context.txt only.
- System: JobCore Candidate Portal (GraphQL), HR Tech/Talent Acquisition
- Host: `api.jobcore-candidate-po.example.com`
- Attacker tenant: `tenant-de5d`, victim tenant: `tenant-fa89`
- HAR mutation: `updateCandidate(id: "C-2309", input: {status: "approved", ownerId: "attacker-de5dfa89"})`, response key: `getCandidate` — **INCONSISTENCY**: HAR uses `updateCandidate` mutation but response key is `getCandidate`. HAR operation is authoritative.
- Response: `ownerId: "other-user-de5dfa89"`, `sensitiveField: "CONFIDENTIAL-de5dfa89"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `candidateId` only (no tenant dimension — secondary vulnerability, candidate PII cache poisoning risk)
- `x-request-id: req-de5dfa89` is a response header (not a request header)
- Pattern 1.1: ID in path without ownership check (BOLA) — `updateCandidate` resolver accepts arbitrary `id` without ownership or tenancy verification; client-supplied `ownerId` in input allows unauthorized ownership reassignment; `getCandidate` resolver also lacks `tenantId` cross-check (RISK-GQL-309)
- §5.0 explicitly states: "attacker with valid `tenant-de5d` token can substitute any `candidateId` value to retrieve objects belonging to `tenant-fa89`"
**Consistency Guard:** All values from this folder's context.txt only.

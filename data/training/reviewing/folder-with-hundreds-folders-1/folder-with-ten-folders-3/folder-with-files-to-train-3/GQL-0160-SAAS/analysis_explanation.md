# Analysis Explanation
**System analysed:** TaskFlow Collaboration API — GQL-0160 (SaaS / Project Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.7: `getProject` nested resources without parent authorization.
2. HAR: `tenant-0621` queries `P-2160` → `tenant-5665`: `CONFIDENTIAL-06215665`, `req-06215665`.
3. SaaS PM: project roadmaps, task assignments — business IP and collaboration data.

## Consistency Guard
Attacker: `tenant-0621`. Victim: `tenant-5665`. Resource: `P-2160`. Sensitive: `CONFIDENTIAL-06215665`. ownerId: `other-user-06215665`. Request: `req-06215665`. All from this folder only.

# Analysis Explanation
**System analysed:** WingTech Maintenance Portal — GQL-0126 (Aerospace / MRO)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 5.2: `bulkResourceLookup` traversal lacks tenancy enforcement at each node — resolver/graph traversal injection.
2. HAR: `tenant-8416` queries `R-2126, R-1126, R-3126` → `tenant-01a9` data: `CONFIDENTIAL-841601a9`, `req-841601a9`.
3. Aerospace/MRO: airworthiness records — FAA/EASA regulatory data, safety directive risk.

## Consistency Guard
Attacker: `tenant-8416`. Victim: `tenant-01a9`. Resources: `R-2126, R-1126, R-3126`. Sensitive: `CONFIDENTIAL-841601a9`. ownerId: `other-user-841601a9`. Request: `req-841601a9`. All from this folder only.

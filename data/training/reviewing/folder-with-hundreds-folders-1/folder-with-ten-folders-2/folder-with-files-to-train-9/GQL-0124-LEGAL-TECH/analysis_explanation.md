# Analysis Explanation
**System analysed:** LexVault eDiscovery API — GQL-0124 (Legal Tech / Document Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-124: `bulkResourceLookup` accepts arbitrary IDs, enabling Pattern 4.2 (persistence poisoning via lifecycle actions).
2. HAR: `tenant-bfc3` queries `R-2124, R-1124, R-3124` → `tenant-2fb9` data: `CONFIDENTIAL-bfc32fb9`, `req-bfc32fb9`.
3. Legal Tech/eDiscovery: legal hold documents — evidence integrity, privilege, and chain-of-custody at risk.

## Consistency Guard
Attacker: `tenant-bfc3`. Victim: `tenant-2fb9`. Resources: `R-2124, R-1124, R-3124`. Sensitive: `CONFIDENTIAL-bfc32fb9`. ownerId: `other-user-bfc32fb9`. Request: `req-bfc32fb9`. All from this folder only.

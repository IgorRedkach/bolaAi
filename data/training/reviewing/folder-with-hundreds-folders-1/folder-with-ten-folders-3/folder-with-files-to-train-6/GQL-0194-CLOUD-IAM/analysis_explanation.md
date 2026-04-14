# Analysis Explanation
**System analysed:** VaultGuard IAM API — GQL-0194 (Cloud IAM / Identity & Access Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-194: `getResource`/`bulkResourceLookup` resolver fetches by `resourceId` only, no `tenantId` check.
2. §5.0 Pattern 7.1: Logging Failures — operational PII/PHI leakage; sensitive identity data returned without tenant filtering.
3. HAR: `tenant-1db2` queries `bulkResourceLookup(ids: ["R-2194", "R-1194", "R-3194"])` → `tenant-387b` IAM records: `CONFIDENTIAL-1db2387b`, `req-1db2387b`.
4. Cloud IAM domain: identity records, role assignments, access policies — privilege escalation and lateral movement risk.

## Consistency Guard
Attacker: `tenant-1db2`. Victim: `tenant-387b`. Resource: `R-2194`. Sensitive: `CONFIDENTIAL-1db2387b`. ownerId: `other-user-1db2387b`. Request: `req-1db2387b`. All from this folder only.

# Analysis Explanation
**System analysed:** LearnPath Assessment Platform — GQL-0216 (Education / Assessment Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-216: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 7.1: Logging Failures — operational PII leakage; student assessment data returned without tenant ownership filter.
3. HAR: `tenant-7a4a` queries `getResource(id: "R-2216")` → `tenant-2b89` student records: `CONFIDENTIAL-7a4a2b89`, `req-7a4a2b89`.
4. Education domain: student grades, assessment scores, learning data — FERPA/COPPA violation.

## Consistency Guard
Attacker: `tenant-7a4a`. Victim: `tenant-2b89`. Resource: `R-2216`. Sensitive: `CONFIDENTIAL-7a4a2b89`. ownerId: `other-user-7a4a2b89`. Request: `req-7a4a2b89`. All from this folder only.

# Analysis Explanation
**System analysed:** GrantFlow CRM API — GQL-0227 (Non-Profit / Grant Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-227: `bulkResourceLookup` has no per-ID `tenantId` ownership check.
2. §5.0 Pattern 1.8: BOLA — predictable/sequential IDs enable systematic enumeration.
3. HAR: `tenant-ef58` calls `bulkResourceLookup(ids: ["R-2227","R-1227","R-3227"])` — IDs are sequential and predictable → `tenant-59c7` grant data returned: `CONFIDENTIAL-ef5859c7`, `req-ef5859c7`.
4. Non-profit domain: grant management, donor PII, beneficiary data — sequential ID enumeration is a systemic cross-org data breach risk.
5. A single bulk request spanning N sequential IDs can exfiltrate entire database in one sweep.

## Consistency Guard
Attacker: `tenant-ef58`. Victim: `tenant-59c7`. Resources: `R-2227`, `R-1227`, `R-3227`. Sensitive: `CONFIDENTIAL-ef5859c7`. ownerId: `other-user-ef5859c7`. Request: `req-ef5859c7`. All from this folder only.

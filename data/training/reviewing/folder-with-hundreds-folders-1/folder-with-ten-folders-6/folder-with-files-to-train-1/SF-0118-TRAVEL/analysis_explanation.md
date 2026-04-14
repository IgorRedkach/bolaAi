# Analysis Explanation
**Example:** SF-0118-TRAVEL — SkyPort Global Distribution
**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)

---

## Why This Is a Vulnerability

Pattern 9.2 (Platform — SOQL and Salesforce record-level access) is specific to the Salesforce authorization model. In Salesforce, record-level access is governed by OWD settings, role hierarchy, and sharing rules. When an Apex class is declared `without sharing`, all of these mechanisms are bypassed — the SOQL executes in a system context. The only remaining protection would be an explicit ownership predicate in the SOQL WHERE clause (`AND OwnerId = :UserInfo.getUserId()`), or `WITH SECURITY_ENFORCED`. `ContractController` has neither. The result is that the SOQL `SELECT ... FROM Contract WHERE Id = :contractId` returns any contract record in the org, regardless of OWD=Private. This is a Salesforce-platform-specific exploitation path: it exploits `without sharing` and missing SOQL ownership enforcement, two Salesforce-specific constructs.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0118.

- **System Name:** SkyPort Global Distribution (§1.0)
- **Domain:** Travel / GDS
- **Host:** `a7fa36be.lightning.force.com` (§6.0 HAR)
- **Session token:** `00DA7FA36BE!ARa7fa36be...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.ContractController.approveContract` (§6.0)
- **Apex class method (§4.0):** `ContractController.getContractDetails`
- **Object type:** Contract (§3.0); OWD: Private (§7.0)
- **Victim record ID:** `00136BE` (§6.0 HAR params)
- **Victim SSN:** `000-62-8515` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `ContractController` declared `without sharing`; no ownership predicate in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex method is `getContractDetails`; §5.0 and §6.0 HAR use `c.ContractController.approveContract`. HAR Aura descriptor is authoritative.

## Domain Risk

Travel / GDS platforms manage airline and hotel contracts, partner agreements, traveler PII (including SSN), and pricing data. Unauthorized access to `SensitiveData__c` (SSN: `000-62-8515`) and `InternalNotes__c` of Contract records in a GDS could expose confidential distribution agreements, partner rates, or traveler personal data — with potential for competitive intelligence theft or traveler identity compromise.

## What the Model Should Learn

- Pattern 9.2 is specifically about the Salesforce SOQL/sharing model: `without sharing` removes OWD enforcement; missing WHERE ownership predicate and `WITH SECURITY_ENFORCED` removes the fallback.
- These two gaps together create a complete record-level access bypass specific to Salesforce's authorization architecture.
- Pattern 9.2 differs from generic BOLA (1.x) in that the exploit path leverages Salesforce's specific `without sharing` / OWD / SOQL constructs, which is a platform-specific vulnerability class.
- The fix requires both: (1) `with sharing` on the class declaration, and (2) ownership check in SOQL.

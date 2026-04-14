# Analysis Explanation
**System analysed:** TrialVault ClinicalOps API — SF-0021 (Pharmaceutical / Clinical Trials, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex code: `LeadController` declared `without sharing` — OWD=Private for Lead bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()` ownership check.
3. §5.0 Pattern 10.2: Session scope extension via parameter escalation — attacker substitutes `leadId` with victim's record ID, extending access beyond their own session scope.
4. HAR: `c.LeadController.getLeadData` with `leadId: "001EFCF"` → `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-97-3761"`.
5. Pharmaceutical/Clinical Trials domain: trial participant PHI, enrollment data, health identifiers — HIPAA/GCP regulated; unauthorized access triggers mandatory breach reporting.
6. `aura.token: "undefined"` — no server-side Aura validation.

## Consistency Guard
Instance: `eda7efcf.lightning.force.com`. Session: `00DEDA7EFCF!AReda7efcf...`. Record: `001EFCF`. OwnerId: `005VICTIM`. SSN: `000-97-3761`. Descriptor: `c.LeadController.getLeadData`. All from this folder only.

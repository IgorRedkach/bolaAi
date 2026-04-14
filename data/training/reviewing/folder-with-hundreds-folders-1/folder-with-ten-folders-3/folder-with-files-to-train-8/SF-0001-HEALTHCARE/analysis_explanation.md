# Analysis Explanation
**System analysed:** PatientCore EHR API (Salesforce-Integrated) — SF-0001 (Healthcare / EHR Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-001: `QuoteController` declared `without sharing` — Salesforce sharing rules not enforced.
2. §4.0 RISK-SF-002: SOQL WHERE clause missing `AND OwnerId = UserInfo.getUserId()` — no ownership check.
3. §5.0 Pattern 1.5: BOLA — multi-tenant access via Aura `quoteId` parameter substitution.
4. HAR: attacker submits `c.QuoteController.getQuoteDetails` with `quoteId: "001E8E7"` → victim record: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-28-7184"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.
5. Healthcare domain: patient SSNs and clinical notes — HIPAA/PHI breach.

## Consistency Guard
Attacker action: `c.QuoteController.getQuoteDetails`. Victim record: `001E8E7`. Victim owner: `005VICTIM`. PHI: `SSN: 000-28-7184`. Internal notes: `CONFIDENTIAL: internal review notes`. aura.token: `undefined`. All from this folder only.

# Analysis Explanation
**System analysed:** ShopGrid Marketplace API (Salesforce-Integrated) — SF-0003 (E-Commerce / Marketplace)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-003: `AccountController` declared `without sharing` — Salesforce sharing rules not enforced.
2. §4.0 RISK-SF-004: SOQL WHERE clause missing ownership check.
3. §5.0 Pattern 2.1: BAC — functional pivot (horizontal); `accountId` substitution enables cross-ownership access.
4. HAR: attacker submits `c.AccountController.getAccounts` with `accountId: "0010CD6"` → victim account: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-55-7150"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.
5. E-Commerce domain: customer SSNs, account notes — identity theft and fraud.

## Consistency Guard
Action: `c.AccountController.getAccounts`. Victim record: `0010CD6`. Victim owner: `005VICTIM`. PII: `SSN: 000-55-7150`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.

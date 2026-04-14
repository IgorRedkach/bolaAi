# Analysis Explanation
**System analysed:** ManuControl Robotics Fleet (Salesforce-Integrated) — SF-0007 (Industrial IoT / Robotics Fleet)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-SF-007: `ContractController` declared `without sharing` — sharing rules not enforced.
2. §4.0 RISK-SF-008: SOQL missing ownership check.
3. §5.0 Pattern 10.2: Single-User — parameter escalation/own session scope extension via `contractId` in Aura action.
4. HAR: attacker submits `c.ContractController.approveContract` with `contractId: "00164BE"` → victim contract: `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-21-9098"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.
5. Industrial IoT domain: robotics fleet contracts — equipment supply chain fraud.

## Consistency Guard
Action: `c.ContractController.approveContract`. Victim record: `00164BE`. Victim owner: `005VICTIM`. PII: `SSN: 000-21-9098`. Notes: `CONFIDENTIAL: internal review notes`. All from this folder only.

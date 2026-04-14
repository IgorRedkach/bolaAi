# Analysis Explanation
**System analysed:** StayPro Property API — SF-0030 (Hospitality / Hotel PMS, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `ContractController` `without sharing` — OWD=Private for Contract bypassed.
2. No SOQL ownership check.
3. §5.0 Pattern 1.12: Mass assignment — client-supplied `fields` array controls Contract fields returned; `approveContract` is a write action that also returns field data.
4. HAR: `c.ContractController.approveContract`, `contractId: "0014589"` → `OwnerId: 005VICTIM`, `SSN: 000-91-7624`.
5. Hospitality: hotel rate agreements, guest contracts — PII and commercial terms exposure.

## Consistency Guard
Instance: `5b594589.lightning.force.com`. Session: `00D5B594589!AR5b594589...`. Record: `0014589`. OwnerId: `005VICTIM`. SSN: `000-91-7624`. Descriptor: `c.ContractController.approveContract`. All from this folder only.

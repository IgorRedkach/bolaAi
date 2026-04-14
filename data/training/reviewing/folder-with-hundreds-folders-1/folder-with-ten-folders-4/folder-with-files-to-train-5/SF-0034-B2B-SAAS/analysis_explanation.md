# Analysis Explanation
**System analysed:** PipelinePro Sales API — SF-0034 (B2B SaaS / CRM, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `ContactController` `without sharing` — OWD=Private bypassed.
2. No SOQL ownership check.
3. §5.0 Pattern 9.2: SOQL record-level access bypass.
4. HAR: `c.ContactController.updateContact`, `contactId: "001D9D2"` → `OwnerId: 005VICTIM`, `SSN: 000-25-4587`.
5. B2B SaaS/CRM domain: sales contacts, deal data, customer PII.

## Consistency Guard
Instance: `a17ad9d2.lightning.force.com`. Session: `00DA17AD9D2!ARa17ad9d2...`. Record: `001D9D2`. OwnerId: `005VICTIM`. SSN: `000-25-4587`. Descriptor: `c.ContactController.updateContact`. All from this folder only.

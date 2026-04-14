# Analysis Explanation
**Folder:** SF-0046-HR | **Context source:** This folder's context.txt only.

## Step-by-step Analysis

### 1. Platform Review (§2.0)
WageFlow Payroll API (SF-0046), HR / Payroll, Salesforce Lightning. OWD = Private on Opportunity object.

### 2. Apex Controller (§4.0)
`OpportunityController` — `public class OpportunityController` without `with sharing`. SOQL: `FROM Opportunity WHERE Id = :opportunityId` — no ownership predicate.

### 3. Pattern 2.4 — Privilege Escalation via Parameter Tampering
The attacker tampers with `opportunityId` to access records outside their scope without needing elevated roles. The server processes the tampered ID as if the attacker were authorized.

### 4. HAR (§6.0)
- Host: `af3580b8.lightning.force.com`, token: `00DAF3580B8!ARaf3580b8...`
- Descriptor: `c.OpportunityController.getOpportunity`, `opportunityId: "00180B8"`
- Response: `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-30-2048`
- RISK-SF-046, RISK-SF-047

### 5. HR / Payroll Domain Impact
Payroll Opportunity records may contain salary negotiation data, compensation packages, and SSN data. `SensitiveData__c: SSN: 000-30-2048` is a direct employee PII breach with payroll fraud implications.

**Consistency Guard:** system `WageFlow Payroll API`, host `af3580b8.lightning.force.com`, token `00DAF3580B8!ARaf3580b8...`, `opportunityId: 00180B8`, `SSN: 000-30-2048`, RISK-SF-046/047, Pattern 2.4 — from this folder's context.txt only.

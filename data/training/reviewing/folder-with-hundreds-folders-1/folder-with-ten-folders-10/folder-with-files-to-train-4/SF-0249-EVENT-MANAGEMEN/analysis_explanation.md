# Analysis Explanation — SF-0249-EVENT-MANAGEMEN

## Changes Made

### 1. Corrected Controller, Object, and Parameter Names
Original used `c.ContactController.updateContact` with `contactId` on Contact object. Context Section 5.0 and HAR specify:
- Controller: `c.ContractController.approveContract`
- Parameter: `contractId`
- Object: Contract (Section 3.0 schema)
Corrected throughout.

### 2. Corrected Org Host and Session Token
Original used `<ORG_ID>.lightning.force.com`. HAR specifies `da3099c4.lightning.force.com` and session token `00DDA3099C4!ARda3099c4...`. Corrected in Step 2 reproduction.

### 3. Explained Pattern 2.4 Correctly
Pattern 2.4 is "Privilege escalation via parameter tampering (BAC)." The key distinction from plain BOLA: `approveContract` is an approval-authority action. By tampering with `contractId` to point to another user's contract, the attacker escalates their privileges to approve contracts they have no authority over — a vertical/horizontal BAC combined with parameter tampering. Added server-side role check for approval authority as a specific remediation.

### 4. Highlighted SSN Exposure
HAR response contains `SensitiveData__c: "SSN: 000-28-5657"`. In Event Management/Ticketing, SSN exposure could represent attendee/contractor PII breach.

### 5. Added Risk ID References
RISK-SF-249 (`without sharing`) and RISK-SF-250 (no ownership check) from Section 8.0 referenced in remediation.

### 6. Method Name Note
Section 4.0 Apex code defines method `getContractDetails`, but Section 5.0 and HAR use `approveContract`. HAR is authoritative — using `approveContract`.

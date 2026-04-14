# Analysis Explanation — SF-0250-PARKING

## Changes Made

### 1. Corrected Controller, Object, and Parameter Names
Original used `c.OpportunityController.getOpportunity` with `opportunityId`. Context Section 5.0 and HAR specify:
- Controller: `c.ContactController.updateContact`
- Parameter: `contactId`
- Object: Contact (Section 3.0 schema)
Corrected throughout.

### 2. Corrected Org Host and Session Token
Original used `<ORG_ID>.lightning.force.com`. HAR specifies `3be99e04.lightning.force.com` and session token `00D3BE99E04!AR3be99e04...`. Corrected in Step 2.

### 3. Explained Pattern 3.1 Correctly
Pattern 3.1 is "Client-assumed authority (Insecure Design)." This is an insecure design pattern where the server is designed to trust whatever the client supplies — it assumes client authority rather than verifying it. Distinguished from plain BOLA: the root cause here is a design decision (no server-side authority check), not just a missing WHERE clause. Added specific Pattern 3.1 remediation: "server must never assume the client has authority over a resource."

### 4. Highlighted SSN Exposure
HAR response contains `SensitiveData__c: "SSN: 000-49-6519"`. Added explicitly in finding and Step 4 verification.

### 5. Risk ID References
RISK-SF-250 (`without sharing`) and RISK-SF-251 (no ownership check) from Section 8.0 referenced in remediation steps.

### 6. Method Name Note
Section 4.0 Apex code defines method `getContactDetails`, but Section 5.0 and HAR both use `updateContact`. HAR and Section 5.0 are authoritative — using `updateContact`.

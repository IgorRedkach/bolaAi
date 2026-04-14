# Analysis Explanation — SF-0244-CLOUD-IAM

## What was wrong

### 1. Wrong controller action, parameter, and object type throughout

Original response used `c.CaseController.getCaseDetails` with `caseId` on a `Case` object. HAR clearly shows `c.OpportunityController.getOpportunity` with `opportunityId` on an `Opportunity` object. Section 4.0 confirms `OpportunityController`. Fixed throughout.

### 2. Generic org host used

Original Step 3 used `<ORG_ID>.lightning.force.com`. HAR shows `3f47cf4a.lightning.force.com`. Fixed.

### 3. SSN from HAR not referenced

HAR response shows `SensitiveData__c: "SSN: 000-32-9515"`. Added explicit reference.

### 4. SOQL injection risk (Section 8.0) not mentioned

Section 8.0 explicitly states: "Client-supplied `opportunityId` is directly interpolated into SOQL without validation" — this is a documented SOQL injection risk beyond the OWD bypass and ownership check failure. Added to evidence and remediation.

### 5. Remediation used wrong controller name

Fixed `CaseController` → `OpportunityController`, `caseId` → `opportunityId`.

### 6. Method name inconsistency noted

Section 4.0 names the method `getOpportunityDetails` but HAR uses `getOpportunity`. HAR is authoritative.

## Domain context

VaultGuard is a Cloud IAM / Identity Provider platform. Opportunity records represent IAM vendor deals, customer identity contracts, or access management proposals. SSN exposure enables identity theft. Internal review notes expose deal negotiation strategy and potentially customer access control architecture details — critical intelligence in an IAM context.

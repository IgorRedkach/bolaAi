# Analysis Explanation — SF-0247-DOCUMENT-SIGNIN

## Changes Made

### 1. Corrected Controller, Object, and Parameter Names
Original used `c.ContactController.updateContact` with `contactId`. Context Section 5.0 and HAR specify:
- Controller: `c.OpportunityController.getOpportunity`
- Parameter: `opportunityId`
- Object: `Opportunity`
Corrected throughout.

### 2. Corrected Org Host and Session Token
Original used generic `<ORG_ID>.lightning.force.com`. HAR specifies `c4dfc988.lightning.force.com` and session token `00DC4DFC988!ARc4dfc988...`. Corrected in Step 2 reproduction.

### 3. Explained Pattern 1.12 Correctly
Pattern 1.12 is "Mass assignment via object fields." In this Salesforce context, the "mass assignment" aspect is the client-controlled `fields` array parameter in the Aura request — the client specifies which fields to return, including sensitive custom fields `SensitiveData__c` and `InternalNotes__c`. Server-side `WITH SECURITY_ENFORCED` or a server-side allowlist would prevent clients from requesting sensitive fields. This is distinct from plain BOLA (which is the `opportunityId` substitution). Both compounding issues are now documented together as Pattern 1.12.

### 4. Highlighted SSN Exposure
HAR response contains `SensitiveData__c: "SSN: 000-52-7113"`. Added explicit SSN PII breach impact in both the finding and Step 4 verification.

### 5. Added Risk IDs
RISK-SF-247 (`without sharing`) and RISK-SF-248 (no ownership check in SOQL) from Section 8.0 are now referenced in the remediation steps.

### 6. Added `WITH SECURITY_ENFORCED` and Server-Side Field Allowlist
Original remediation only addressed `with sharing` and SOQL ownership check. Since Pattern 1.12 involves client-controlled field selection, added `WITH SECURITY_ENFORCED` in SOQL and server-side field allowlist as specific remediations for the mass assignment aspect.

### 7. Noted Method Name Inconsistency
Section 4.0 Apex code defines method `getOpportunityDetails`, but Section 5.0 and HAR use `getOpportunity`. HAR is authoritative — using `getOpportunity`.

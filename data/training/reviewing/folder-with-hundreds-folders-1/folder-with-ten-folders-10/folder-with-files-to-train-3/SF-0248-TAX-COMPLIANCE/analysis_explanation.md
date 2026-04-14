# Analysis Explanation — SF-0248-TAX-COMPLIANCE

## Changes Made

### 1. Corrected Controller, Object, and Parameter Names
Original used `c.QuoteController.getQuoteDetails` with `quoteId`. Context Section 5.0 and HAR specify:
- Controller: `c.ContactController.updateContact`
- Parameter: `contactId`
- Object: Contact (Section 3.0 schema)
Corrected throughout.

### 2. Corrected Org Host and Session Token
Original used `<ORG_ID>.lightning.force.com`. HAR specifies `9532bce9.lightning.force.com` and session token `00D9532BCE9!AR9532bce9...`. Corrected in Step 2 reproduction.

### 3. Explained Pattern 2.1 Correctly
Pattern 2.1 is "Functional pivot (vertical/horizontal) (BAC)." In this context, the `updateContact` action is intended for the authenticated user's own Contact. The attacker pivots the function horizontally to operate on any other user's Contact record. Distinguished from plain BOLA by emphasizing that the function itself (contact update/read) is being repurposed across user boundaries — a BAC functional pivot rather than a simple ID substitution.

### 4. Highlighted SSN Exposure in Tax Compliance Context
HAR response contains `SensitiveData__c: "SSN: 000-61-8487"`. In Tax Compliance/RegTech domain, SSN exposure has direct SOX/GLBA compliance implications (financial data PII). Added explicitly in finding and Step 4 verification.

### 5. Risk ID References
RISK-SF-248 (`without sharing`) and RISK-SF-249 (no ownership check) from Section 8.0 are now referenced in the remediation steps.

### 6. Method Name Inconsistency Note
Section 4.0 Apex code defines method `getContactDetails`, but Section 5.0 and HAR use `updateContact`. HAR is authoritative — using `updateContact`.

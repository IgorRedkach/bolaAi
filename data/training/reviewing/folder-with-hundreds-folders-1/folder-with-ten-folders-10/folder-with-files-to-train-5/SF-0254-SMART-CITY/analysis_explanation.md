# Analysis Explanation — SF-0254-SMART-CITY

## Changes Made

### 1. context.txt — Removed Vulnerability Labels, Added FLS Context
- Section 5.0 "Vulnerability Context" renamed to "Behavioral Notes"; removed "**Pattern:** 1.12 — Mass assignment via object fields" label
- Section 4.0 Apex code: removed "// VULNERABILITY:" comments; added `String.join(fields, ', ')` concatenation to show the `fields` array is used directly in SELECT — this is the evidence for the mass assignment
- Section 7.0 Sharing Rule Configuration: added "Field Level Security: SensitiveData__c and InternalNotes__c are restricted to Admin profile only" — this is critical evidence for Pattern 1.12
- Section 8.0: added "Client-supplied `fields` array is concatenated directly into SELECT without FLS validation" as a risk note
- HAR message params corrected to use escaped JSON

### 2. expected_response.md — Corrected Controller and Parameters
Original used `c.CaseController.getCaseDetails` with `caseId`. HAR specifies `c.LeadController.getLeadData` with `leadId`. Corrected throughout.

### 3. Corrected Org Host and Session Token
Original used `<ORG_ID>.lightning.force.com`. HAR specifies `43649678.lightning.force.com` and `00D43649678!AR43649678...`. Corrected.

### 4. Explained Pattern 1.12 — Mass Assignment via `fields` Array
Pattern 1.12 is specifically "mass assignment via object fields." The HAR shows the client sending `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]` and receiving all of them including FLS-restricted fields. Made mass assignment (client-controlled `fields` array bypassing FLS) the primary finding, with cross-user `leadId` as the combined attack.

### 5. Added FLS-Specific Remediation
Added Apex DescribeFieldResult FLS check as the specific remediation for Pattern 1.12, alongside `with sharing` and ownership filter.

### 6. Method Name Note
Section 4.0 code defines `getLeadDetails`; HAR uses `getLeadData`. HAR is authoritative; Section 4.0 code shows the internal implementation.

# Analysis Explanation — SF-0268-TRAVEL

## What was wrong

### 1. Wrong controller action, parameter, and object type throughout

Original response used `c.LeadController.getLeadData` with `leadId` parameter. HAR clearly shows `c.CaseController.getCaseDetails` with `caseId` parameter on a `Case` object. Section 4.0 confirms `CaseController` and `getCaseDetails`. Fixed throughout.

### 2. Generic org host used

Original Step 3 used `<ORG_ID>.lightning.force.com`. HAR shows the actual host: `fbceb7dd.lightning.force.com`. Fixed.

### 3. Pattern 1.12 (mass assignment via fields) not demonstrated

Pattern 1.12 is Mass Assignment via Object Fields. The original response treated this as a simple BOLA read without explaining the mass assignment component. The HAR shows a client-supplied `fields` array: `["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`. This is the mass assignment vector: the client controls which fields are returned by the server. Added Step 3 to demonstrate field manipulation and added server-side whitelist as the primary remediation for Pattern 1.12.

### 4. SSN exposure from HAR not specifically referenced

HAR response shows `SensitiveData__c: "SSN: 000-37-3629"`. Original response mentioned `SensitiveData__c` generically. Added specific SSN reference.

### 5. Remediation used wrong controller name

Fixed `LeadController` → `CaseController`, `leadId` → `caseId`.

## Domain context

SkyPort is a Travel / GDS platform. Case records represent travel support tickets, passenger booking disputes, or airline complaint cases. SSN exposure enables traveler identity theft. Client-controlled `fields` parameter (Pattern 1.12) allows the attacker to exfiltrate fields beyond what the application UI would normally display — all custom fields on the Case object become accessible.

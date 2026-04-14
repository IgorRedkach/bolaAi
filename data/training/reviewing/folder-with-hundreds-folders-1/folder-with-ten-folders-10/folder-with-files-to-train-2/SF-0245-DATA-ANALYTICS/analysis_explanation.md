# Analysis Explanation — SF-0245-DATA-ANALYTICS

## What was wrong

### 1. Wrong controller action and parameter throughout

Original response used `c.LeadController.getLeadData` with `leadId`. HAR shows `c.CustomObjectController.getRecord` with `recordId`. Section 5.0 also confirms `c.CustomObjectController.getRecord`. Fixed throughout.

### 2. Generic org host used

Original Step 3 used `<ORG_ID>.lightning.force.com`. HAR shows `94e8d145.lightning.force.com`. Fixed.

### 3. SSN from HAR not referenced

HAR response shows `SensitiveData__c: "SSN: 000-99-4930"`. Added explicit reference.

### 4. Pattern 10.2 (parameter escalation / session scope extension) not explained

Original response described a simple BOLA read. Pattern 10.2 (Parameter Escalation — Own Session Scope Extension) requires explaining that the attacker's session is legitimately authenticated, but the `recordId` parameter escalates the session's authorized scope beyond what it was granted. The attack is not about stolen sessions — it's about extending a valid session's scope by substituting parameter values that should be session-bounded. Added explanation.

### 5. Remediation used wrong controller name

Fixed `LeadController` → `CustomRecordController`.

### 6. Method name inconsistency noted

Section 4.0 names the class `CustomRecordController` with method `getCustomRecordDetails` but HAR uses `CustomObjectController.getRecord`. HAR is authoritative.

## Domain context

InsightGraph is a Data Analytics / BI Platform. `CustomRecord` represents analytics dashboards, BI reports, or data pipeline configurations. Parameter escalation (Pattern 10.2) allows an analyst to extend their session scope from their own BI reports to all other analysts' proprietary reports and dashboard configurations. SSN in analytics records suggests PHI or PII was included in dataset processing — CCPA/GDPR violation.

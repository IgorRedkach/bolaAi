# Analysis Explanation — SF-0267-REAL-ESTATE

## What was wrong

### 1. Wrong controller action name and parameter

Original response used `c.CustomObjectController.getRecord` with `recordId` parameter. HAR clearly shows `c.AccountController.getAccounts` with `accountId` parameter. Section 5.0 also confirms `c.AccountController.getAccounts`. Fixed throughout.

### 2. SSN exposure from HAR not highlighted

HAR response includes `SensitiveData__c: "SSN: 000-77-1919"` — critical PII exposure. Original response mentioned `SensitiveData__c` generically but did not reference the specific SSN value from the HAR. Added explicit reference to `SSN: 000-77-1919` as the primary PII evidence.

### 3. Two distinct root causes (RISK-SF-267 and RISK-SF-268) not clearly separated

Original response combined the two risks. Clearly articulated both:
- RISK-SF-267: controller declared `without sharing` (bypasses OWD=Private)
- RISK-SF-268: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED`

### 4. Remediation used wrong controller name

Original remediation used `CustomRecordController`. Fixed to `AccountController`.

### 5. Method name inconsistency noted

Section 4.0 names the method `getAccountDetails` but HAR and Section 5.0 use `getAccounts`. HAR is authoritative — `getAccounts` is the correct production action name. Noted in response.

## Domain context

EstateFlow is a Real Estate / PropTech platform. Account records represent property buyers, sellers, and broker accounts. SSN exposure (`SensitiveData__c: "SSN: 000-77-1919"`) from cross-tenant access enables identity theft and violates CCPA/GDPR and state privacy laws. Internal review notes (`InternalNotes__c`) expose negotiation strategies and due diligence data — critical competitive intelligence in real estate transactions.

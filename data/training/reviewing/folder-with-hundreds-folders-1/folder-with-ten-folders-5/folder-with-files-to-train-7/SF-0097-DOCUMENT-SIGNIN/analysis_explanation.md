# Analysis Explanation
**Folder:** SF-0097-DOCUMENT-SIGNIN | **Context source:** This folder's context.txt only.
- System: SignFlow eSign Platform (SF), Document Signing/eSign, OWD: Private on Opportunity
- Host: `a8e397bc.lightning.force.com`, token: `00DA8E397BC!ARa8e397bc...`
- Descriptor (HAR): `c.OpportunityController.getOpportunity`, `opportunityId: "00197BC"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getOpportunityDetails` but Aura descriptor in §6.0 is `getOpportunity`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-78-1970`
- Pattern 9.2: SOQL and Salesforce record-level access bypass (Platform) — `without sharing` silently bypasses Salesforce platform's OWD=Private enforcement at the SOQL layer; missing `WITH SECURITY_ENFORCED` means Salesforce FLS/CRUD checks are also skipped; attacker reads any Opportunity record owned by any user
- §8.0 RISK-SF-097/098: controller without `with sharing`; no ownership check; client-supplied `opportunityId` directly interpolated
**Consistency Guard:** All values from this folder's context.txt only.

## Analysis reasoning

I reviewed the NexaBank Open Finance API (Salesforce-Integrated) v1.2.0 architecture, Apex controller code, and HAR trace.

1. **Critical error in the original expected_response.md**: the document named the vulnerable controller `c.LeadController.getLeadData` with parameter `leadId`. The actual context uses `c.ContactController.updateContact` (HAR section 6.0) and `ContactController.getContactDetails` with parameter `contactId` (section 4.0). These are entirely different Salesforce object types. The controller name mismatch makes the reproduction steps non-functional.

2. **Same dual-vulnerability pattern as SF-0001**: `without sharing` (RISK-SF-002) bypasses OWD=Private, and missing `OwnerId` in SOQL (RISK-SF-003) means even if sharing were added, there's no explicit ownership filter. Both must be fixed.

3. **SSN in response is definitive financial PII**: response `"SensitiveData__c": "SSN: 000-71-5059"` — Social Security Number in a retail banking system's Contact record constitutes GLBA-regulated customer financial information. Unauthorized access violates the GLBA Privacy Rule (16 CFR Part 313).

4. **HAR descriptor `updateContact` vs. code `getContactDetails`**: the HAR shows the `updateContact` action descriptor but the Apex code shows `getContactDetails`. This is a similar pattern to GQL-0001's request/response mismatch — the HAR is a synthetic artifact where the descriptor name may be slightly inconsistent. The important signal is: the attacker authenticated, sent a valid Aura request with an arbitrary `contactId`, and received the victim's SSN. Both the read and write paths are vulnerable given the same missing checks.

5. **Pattern 1.12 (Mass assignment) context**: section 5.0 labels this Pattern 1.12. In the Salesforce context, this refers to the `contactId` parameter being accepted without field-level restriction — the controller processes any ID supplied without validating against the user's owned Contact records.

# Analysis Explanation
**Folder:** SF-0058-GOVERNMENT | **Context source:** This folder's context.txt only.
- System: FirstResponse CAD Integration, Government/Emergency Dispatch, OWD: Private on Case
- Host: `75577115.lightning.force.com`, token: `00D75577115!AR75577115...`
- Descriptor: `c.CaseController.getCaseDetails`, `caseId: "0017115"` (CONSISTENT — method and descriptor both use `getCaseDetails`)
- Response: `OwnerId: 005VICTIM`, `SSN: 000-44-4984`
- Pattern 1.12: Client-supplied `fields` array has no server-side allowlist; attacker enumerates all object fields including PHI/PII (`SensitiveData__c`, `InternalNotes__c`). Combined with missing ownership predicate, full CAD incident record is returned.
- Government-critical: citizen SSN exposure in emergency dispatch records.
**Consistency Guard:** All values from this folder's context.txt only.

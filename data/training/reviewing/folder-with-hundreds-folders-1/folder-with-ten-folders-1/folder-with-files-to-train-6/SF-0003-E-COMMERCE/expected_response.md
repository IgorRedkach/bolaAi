## System

- System: ShopGrid Marketplace API (Salesforce-Integrated) v1.7.0
- Domain: E-COMMERCE / MARKETPLACE
- Example ID: SF-0003
- Risk IDs: RISK-SF-003, RISK-SF-004

## Findings

### 1. Salesforce Aura BOLA — Functional Pivot via Unauthorized Account Access (Pattern 2.1)

The Aura controller action `c.AccountController.getAccounts` exposes an `accountId` parameter. The Apex class is declared `public class AccountController` without `with sharing` (RISK-SF-003). The SOQL query filters only by ID:

```apex
'FROM Account WHERE Id = :' + accountId
// Missing: AND OwnerId = UserInfo.getUserId()
// Missing: WITH SECURITY_ENFORCED
```

The Account object's OWD is `Private` (section 7.0). The `without sharing` declaration bypasses Salesforce sharing enforcement. Section 5.0 describes a functional pivot (Pattern 2.1): a lower-privileged user accesses Account records owned by other users — in a marketplace context, this is horizontal privilege escalation across merchant accounts.

**HAR evidence**: Aura `POST /aura` to `5ccd0cd6.lightning.force.com` with session token `00D5CCD0CD6!...`. Request action descriptor: `c.AccountController.getAccounts`. Injected `accountId: "0010CD6"` (belongs to `OwnerId: 005VICTIM`). Response state: `SUCCESS`. Response body: `"InternalNotes__c": "CONFIDENTIAL: internal review notes"` and `"SensitiveData__c": "SSN: 000-55-7150"` — victim's Account data returned to the attacker.

**E-commerce marketplace impact**: Account records in a Salesforce marketplace platform contain merchant account details, payment terms, credit agreements, and business PII. An attacker reading a competitor's Account `InternalNotes__c` gains access to negotiated pricing, credit lines, or contract notes. The SSN in `SensitiveData__c` (likely a sole-proprietor merchant's personal SSN) is financial PII protected under GLBA.

## Evidence

- **Section 4.0** (Apex code): `public class AccountController` — no `with sharing`; SOQL `WHERE Id = :accountId` — no `OwnerId` predicate; missing `WITH SECURITY_ENFORCED`.
- **Section 7.0**: Account OWD = Private; controller without `with sharing`.
- **RISK-SF-003**: controller without sharing — sharing rules not enforced.
- **RISK-SF-004**: no ownership check in SOQL.
- **HAR**: attacker JWT → `c.AccountController.getAccounts(accountId: "0010CD6")` → HTTP 200 → `state: SUCCESS` → `SensitiveData__c: SSN: 000-55-7150`.

## Reproduction

**Step 1 — Capture a baseline Aura request to your own Account record:**

Intercept a legitimate Aura request via Burp Suite or browser DevTools. Identify the `c.AccountController.getAccounts` action. Record your own `accountId`.

**Step 2 — Substitute victim `accountId` (primary HAR attack):**

```
POST https://5ccd0cd6.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D5CCD0CD6!AR5ccd0cd6...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D5CCD0CD6!AR5ccd0cd6...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"0010CD6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure outcome: `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records`.  
Expected vulnerable outcome: HTTP 200, `state: "SUCCESS"`, response with `SensitiveData__c: SSN: 000-55-7150`.

**Step 3 — Enumerate Account records:**

Salesforce Account IDs use a `001` prefix. Enumerate `accountId` values starting with `001` to discover competitor merchant Account records.

## Remediation

- **Add `with sharing` to Apex class** (RISK-SF-003):
  ```apex
  public with sharing class AccountController { ... }
  ```
- **Add `OwnerId` filter to SOQL** (RISK-SF-004):
  ```apex
  'FROM Account WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()'
  ```
- **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
- **Validate `accountId` against accessible records**: use `[SELECT Id FROM Account WHERE OwnerId = :UserInfo.getUserId()]` before querying.
- **Automated regression test**: authenticate as User A, request User B's Account ID — assert `AuraHandledException` or empty result.

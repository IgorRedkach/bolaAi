# Expected Response

## System
- System: NexaBank Open Finance API (Salesforce-Integrated) v4.3.0
- Domain: FINANCIAL SERVICES / RETAIL BANKING
- Example ID: SF-0252
- Risk IDs: RISK-SF-252, RISK-SF-253

## Findings

### 1. Pattern 10.2 — Parameter Escalation (Own Session Scope Extension): `c.AccountController.getAccounts` (HAR Primary)

The Aura controller `c.AccountController.getAccounts` accepts a client-supplied `accountId`. Pattern 10.2 "parameter escalation (own session scope extension)" — a user with a legitimate session for their own Account record substitutes a different `accountId` in the Aura payload to extend their session's access scope to records they do not own. The `without sharing` class (RISK-SF-252) bypasses OWD=Private, and the missing `OwnerId` predicate (RISK-SF-253) means the scope extension succeeds.

In Financial Services / Retail Banking, Account records contain customer banking relationships, SSN PII, and GLBA-protected financial data. Session scope extension enables any authenticated bank employee or customer to access another customer's account record — GLBA financial privacy violation.

**Evidence from HAR:**
- Aura action: `c.AccountController.getAccounts`
- Requested `accountId`: `001CFAD` — belongs to `OwnerId: "005VICTIM"`
- Session user's org: `7d68cfad.lightning.force.com`
- Response state: `SUCCESS` — session scope extended to victim's Account
- Response includes `SensitiveData__c: "SSN: 000-71-4238"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — PII/financial data exposed

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify `c.AccountController.getAccounts` in the `message` POST body.
Record your own `accountId`.

**Step 2 — Substitute victim `accountId` — session scope extension (primary HAR attack):**
```
POST https://7d68cfad.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D7D68CFAD!AR7d68cfad...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D7D68CFAD!AR7d68cfad...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"001CFAD","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Step 3 — Enumerate adjacent Account IDs:**
```
accountId: 001CFAC, 001CFAE, 001CFAF, ...
```

**Step 4 — Verify session scope extension:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with victim Account data including:
- `SensitiveData__c: "SSN: 000-71-4238"` — SSN exposed (GLBA financial privacy violation)
- `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — internal banking notes
- `OwnerId: "005VICTIM"` — session extended to another user's record

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class (RISK-SF-252):**
   ```apex
   public with sharing class AccountController { ... }
   ```
2. **Add ownership filter to SOQL (RISK-SF-253):**
   ```apex
   WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Use `WITH SECURITY_ENFORCED` in all SOQL queries** to enforce field-level and record-level security.
4. **Automated test:** Apex test authenticating as User A requesting User B's `accountId` — assert `INSUFFICIENT_ACCESS` or empty result.

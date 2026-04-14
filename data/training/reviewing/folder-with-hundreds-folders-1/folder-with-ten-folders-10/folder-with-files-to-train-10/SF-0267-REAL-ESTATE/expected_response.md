## System

- System: EstateFlow Property API (Salesforce-Integrated) v3.7.0
- Domain: REAL ESTATE / PROPTECH
- Example ID: SF-0267
- Risk IDs: RISK-SF-267, RISK-SF-268

## Findings

### 1. Pattern 1.5 — Cross-Tenant Salesforce Account Access: `c.AccountController.getAccounts` (HAR Primary)

**HAR evidence**: Aura action `c.AccountController.getAccounts` with `accountId: "0016C75"`, fields: `["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`. Response: `state: "SUCCESS"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-77-1919"`.

**Pattern 1.5 (Multi-Tenant / Cross-Tenant Access)**: Section 7.0 — `Account OWD: Private` — users should only access Account records they own or were explicitly shared with. The Apex controller `AccountController` is declared `without sharing` (Section 4.0 and Section 7.0), bypassing OWD=Private sharing rules entirely (RISK-SF-267). Section 4.0: SOQL query filters only by `accountId` — missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` (RISK-SF-268). An attacker substitutes any `accountId` in the Aura framework POST to access any other buyer/seller/broker Account record in the org.

**Real Estate / PropTech impact**: Account records represent property buyers, sellers, and broker accounts including SSN (`SensitiveData__c: "SSN: 000-77-1919"`), financial data, and internal review notes (`InternalNotes__c`). Cross-tenant exposure enables identity theft, competitive intelligence gathering, and unauthorized access to all property transaction parties. SSN exposure violates CCPA/GDPR and state privacy laws.

Note: Section 4.0 names the method `getAccountDetails` but HAR uses `getAccounts`. HAR is authoritative — `getAccounts` is the correct production action name.

## Reproduction

**Step 1 — Capture baseline Aura request:**

Intercept a legitimate Aura request via Burp Suite or browser DevTools. Identify `c.AccountController.getAccounts` in the `message` POST body. Record your own `accountId` (e.g., `001YOURID`).

**Step 2 — Substitute victim `accountId` (primary HAR attack):**

```
POST https://be866c75.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DBE866C75!ARbe866c75...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DBE866C75!ARbe866c75...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"0016C75","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure: `state: "ERROR"` / INSUFFICIENT_ACCESS / empty `records`.  
Expected vulnerable: `state: "SUCCESS"` with `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-77-1919"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.

**Step 3 — Enumerate other Account IDs:**

Salesforce Account IDs follow `001` prefix + 15 character alphanumeric. Increment or enumerate to access all buyer/seller/broker records across the org.

## Evidence

- **HAR**: `c.AccountController.getAccounts` with `accountId: "0016C75"` → `SUCCESS` → `SensitiveData__c: "SSN: 000-77-1919"`, `OwnerId: "005VICTIM"`.
- **Section 4.0**: Apex controller declared `public class AccountController` (no `with sharing`) — RISK-SF-267.
- **Section 4.0**: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` — RISK-SF-268.
- **Section 7.0**: `Account OWD: Private` — sharing rules should protect records but are bypassed by `without sharing`.

## Remediation

1. **Add `with sharing` to Apex class** (RISK-SF-267):
   ```apex
   public with sharing class AccountController { ... }
   ```
2. **Add ownership filter to SOQL** (RISK-SF-268):
   ```apex
   WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
4. **Validate `accountId`** against user's accessible record list before querying.
5. **Regression test**: Apex test authenticates as User A, requests User B's `accountId` — assert `INSUFFICIENT_ACCESS` or empty `records`.

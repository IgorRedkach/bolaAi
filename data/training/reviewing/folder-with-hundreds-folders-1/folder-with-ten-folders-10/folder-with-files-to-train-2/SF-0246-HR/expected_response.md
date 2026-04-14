## System

- System: WageFlow Payroll API (Salesforce-Integrated) v2.3.0
- Domain: HR / PAYROLL PROCESSING
- Example ID: SF-0246
- Risk IDs: RISK-SF-246, RISK-SF-247

## Findings

### 1. Pattern 1.5 — Cross-Tenant Salesforce Account Access: `c.AccountController.getAccounts` (HAR Primary)

**HAR evidence**: Aura action `c.AccountController.getAccounts` with `accountId: "001DDE1"`, client-supplied `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`. Response: `state: "SUCCESS"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-35-4589"`.

**Pattern 1.5 (Multi-Tenant / Cross-Tenant Access)**: Section 7.0 — `Account OWD: Private`. The controller `AccountController` runs `without sharing` (Section 7.0, RISK-SF-246), bypassing OWD=Private entirely. SOQL filters only by `accountId` — missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` (Section 4.0, RISK-SF-247). An attacker with a valid Salesforce session substitutes any `accountId` to access any employer or employee Account record in the org.

**HR / Payroll impact**: Account records in WageFlow represent employer payroll accounts, employee payroll profiles, or contractor billing records. SSN exposure (`SensitiveData__c: "SSN: 000-35-4589"`) enables identity theft and payroll fraud. Internal notes expose salary negotiation details and payroll configurations. Cross-tenant access by a competing employer allows intelligence gathering on another company's payroll structure. GLBA and state payroll data protection laws are violated.

Note: Section 4.0 names the method `getAccountDetails` but HAR uses `getAccounts`. HAR is authoritative.

## Reproduction

**Step 1 — Capture baseline Aura request:**

Intercept a legitimate Aura request via Burp Suite or DevTools. Identify `c.AccountController.getAccounts` in the `message` body. Record your own `accountId`.

**Step 2 — Substitute victim `accountId` (primary HAR attack):**

```
POST https://11bcdde1.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D11BCDDE1!AR11bcdde1...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D11BCDDE1!AR11bcdde1...

message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN",
"params":{"accountId":"001DDE1","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure: `state: "ERROR"` / INSUFFICIENT_ACCESS / empty `records`.  
Expected vulnerable: `state: "SUCCESS"` with `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-35-4589"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.

**Step 3 — Enumerate additional Account IDs for mass payroll data theft:**

Salesforce Account IDs use `001` prefix. Enumerate to access all employer/employee Account records across the payroll org.

## Evidence

- **HAR**: `c.AccountController.getAccounts` with `accountId: "001DDE1"` → `SUCCESS` → `SensitiveData__c: "SSN: 000-35-4589"`, `OwnerId: "005VICTIM"`.
- **Section 4.0**: Apex controller declared `public class AccountController` (no `with sharing`) — RISK-SF-246.
- **Section 4.0**: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` — RISK-SF-247.
- **Section 7.0**: `Account OWD: Private` — sharing rules bypassed.

## Remediation

1. **Add `with sharing` to Apex class** (RISK-SF-246):
   ```apex
   public with sharing class AccountController { ... }
   ```
2. **Add ownership filter to SOQL** (RISK-SF-247):
   ```apex
   WHERE Id = :accountId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
4. **Validate `accountId`** against user's accessible record list before querying.
5. **Whitelist allowed fields server-side**: do not accept client-supplied `fields` array.
6. **Regression test**: Apex test authenticates as User A, requests User B's `accountId` — assert `INSUFFICIENT_ACCESS` or empty `records`.

# Expected Response

## System
- System: ShopGrid Marketplace API (Salesforce-Integrated) v1.6.0
- Domain: E-COMMERCE / MARKETPLACE
- Example ID: SF-0253
- Risk IDs: RISK-SF-253, RISK-SF-254

## Findings

### 1. Pattern 1.5 — Cross-Tenant/Cross-Seller Contract Access: `c.ContractController.approveContract` (HAR Primary)

The Aura controller `c.ContractController.approveContract` accepts a client-supplied `contractId`. Pattern 1.5 "multi-tenant / cross-tenant access" — one marketplace seller can access or approve contracts belonging to another seller by substituting the `contractId`. The `without sharing` class (RISK-SF-253) bypasses OWD=Private, and the missing `OwnerId` predicate (RISK-SF-254) means cross-seller access succeeds.

In E-Commerce / Marketplace, Contract records contain seller agreements, pricing terms, vendor SSN PII, and payment processor configurations. Cross-seller access enables competitor intelligence gathering and unauthorized contract approval — a significant marketplace integrity violation.

**Evidence from HAR:**
- Aura action: `c.ContractController.approveContract`
- Requested `contractId`: `001C647` — belongs to `OwnerId: "005VICTIM"` (another seller)
- Session: `57ebc647.lightning.force.com` — request came from authenticated marketplace user
- Response state: `SUCCESS` — cross-seller contract approved without authorization check
- Response includes `SensitiveData__c: "SSN: 000-78-9611"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — vendor PII exposed

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify `c.ContractController.approveContract` in the `message` POST body.
Record your own `contractId`.

**Step 2 — Substitute victim `contractId` — cross-seller contract access (primary HAR attack):**
```
POST https://57ebc647.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D57EBC647!AR57ebc647...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D57EBC647!AR57ebc647...

message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN",
"params":{"contractId":"001C647","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Step 3 — Enumerate adjacent Contract IDs (marketplace sellers):**
```
contractId: 001C646, 001C648, 001C649, ...
```

**Step 4 — Verify cross-tenant access:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with victim seller's Contract data including:
- `SensitiveData__c: "SSN: 000-78-9611"` — vendor SSN exposed
- `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — private seller notes
- `OwnerId: "005VICTIM"` — contract belongs to a different seller; cross-tenant access confirmed

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class (RISK-SF-253):**
   ```apex
   public with sharing class ContractController { ... }
   ```
2. **Add ownership filter to SOQL (RISK-SF-254):**
   ```apex
   WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Use `WITH SECURITY_ENFORCED` in all SOQL queries** to enforce record-level security.
4. **Automated test:** Apex test authenticating as Seller A requesting Seller B's `contractId` — assert `INSUFFICIENT_ACCESS` or empty result.

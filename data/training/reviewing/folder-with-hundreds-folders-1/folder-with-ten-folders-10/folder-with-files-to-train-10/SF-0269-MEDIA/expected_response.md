## System

- System: StreamCore VOD Platform (Salesforce-Integrated) v4.3.0
- Domain: MEDIA / CONTENT DELIVERY
- Example ID: SF-0269
- Risk IDs: RISK-SF-269, RISK-SF-270

## Findings

### 1. Pattern 2.1 — Functional Pivot: Unauthorized Task Record Access via `c.TaskController.getTask` (HAR Primary)

**HAR evidence**: Aura action `c.TaskController.getTask` with `taskId: "0012A04"`, client-supplied `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`. Response: `state: "SUCCESS"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-24-9729"`.

**Pattern 2.1 (Functional Pivot — Broken Access Control)**: the controller's `without sharing` declaration allows both horizontal and functional pivots. Horizontal pivot: attacker accesses Task records owned by other users (`OwnerId: "005VICTIM"` ≠ attacker's ID). Functional pivot: `getTask` is a Task management function not intended for cross-user access — the attacker pivots into the functional scope of another user's Task operations by substituting `taskId`. Section 7.0 — `Task OWD: Private` — should restrict access to owned records, but RISK-SF-269 (`without sharing`) fully bypasses this. RISK-SF-270: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED`.

**Media / Content Delivery impact**: Task records represent content review workflows, streaming infrastructure management tasks, or content rights management activities. Cross-user Task access exposes content pipeline internals, review decisions, and `SensitiveData__c` (SSN: `000-24-9729`) from other content managers. Internal review notes expose editorial and rights strategy.

Note: Section 4.0 names the method `getTaskDetails` but HAR uses `getTask`. HAR is authoritative.

## Reproduction

**Step 1 — Capture baseline Aura request:**

Intercept a legitimate Aura request via Burp Suite or DevTools. Identify `c.TaskController.getTask` in the `message` body. Record your own `taskId`.

**Step 2 — Substitute victim `taskId` — functional pivot (primary HAR attack):**

```
POST https://11682a04.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D11682A04!AR11682a04...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D11682A04!AR11682a04...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN",
"params":{"taskId":"0012A04","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure: `state: "ERROR"` / INSUFFICIENT_ACCESS / empty `records`.  
Expected vulnerable: `state: "SUCCESS"` with `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-24-9729"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.

**Step 3 — Enumerate additional Task IDs for mass horizontal pivot:**

Salesforce Task IDs use `00T` prefix (standard Task object). Enumerate to access all content team Task records in the org.

## Evidence

- **HAR**: `c.TaskController.getTask` with `taskId: "0012A04"` → `SUCCESS` → `SensitiveData__c: "SSN: 000-24-9729"`, `OwnerId: "005VICTIM"`.
- **Section 4.0**: Apex controller declared `public class TaskController` (no `with sharing`) — RISK-SF-269.
- **Section 4.0**: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` — RISK-SF-270.
- **Section 7.0**: `Task OWD: Private` — sharing rules bypassed by `without sharing`.

## Remediation

1. **Add `with sharing` to Apex class** (RISK-SF-269):
   ```apex
   public with sharing class TaskController { ... }
   ```
2. **Add ownership filter to SOQL** (RISK-SF-270):
   ```apex
   WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
4. **Whitelist allowed fields server-side**: do not accept client-supplied `fields` array.
5. **Regression test**: Apex test authenticates as User A, requests User B's `taskId` — assert `INSUFFICIENT_ACCESS` or empty `records`.

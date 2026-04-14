# Analysis Explanation

**Folder:** SF-0043-SMART-HOME
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Platform Review (§2.0)
NeoBuild BAS Platform (SF-0043) is a smart home / building automation system on Salesforce Lightning. OWD = Private on Task object. Auth: Salesforce Session ID.

### 2. Apex Controller (§4.0)
`TaskController` declared `public class TaskController` — without `with sharing`. SOQL: `FROM Task WHERE Id = :taskId` — no ownership predicate, no `WITH SECURITY_ENFORCED`.

### 3. Context Inconsistency
§4.0 defines `getTaskDetails(String taskId, ...)`. HAR descriptor (§6.0) shows `c.TaskController.getTask`. Both reference the same class without sharing. Documented as-is.

### 4. Pattern 1.5 — Multi-tenant/cross-tenant access
Cross-tenant BOLA: an attacker on one tenant/user account accesses records owned by a different user by substituting the `taskId` parameter. No server-side tenancy guard exists.

### 5. HAR (§6.0)
- Host: `41285d43.lightning.force.com`, token: `00D41285D43!AR41285d43...`
- Descriptor: `c.TaskController.getTask`, `taskId: "0015D43"`
- Response: `Id: 0015D43`, `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-47-7431`
- RISK-SF-043 (no `with sharing`), RISK-SF-044 (no ownership predicate)

### 6. Domain Impact
BAS Task records may contain building access schedules, HVAC maintenance orders, and security system configuration tasks. SSN exposure is a direct PII breach.

---
**Consistency Guard:** system `NeoBuild BAS Platform`, host `41285d43.lightning.force.com`, token `00D41285D43!AR41285d43...`, descriptor `c.TaskController.getTask`, `taskId: 0015D43`, `SSN: 000-47-7431`, RISK-SF-043/044, Pattern 1.5 — all from this folder's context.txt only.

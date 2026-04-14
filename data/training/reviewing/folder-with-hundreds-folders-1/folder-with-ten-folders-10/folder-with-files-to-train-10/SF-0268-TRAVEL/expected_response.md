## System

- System: SkyPort Global Distribution (Salesforce-Integrated) v2.9.0
- Domain: TRAVEL / GDS
- Example ID: SF-0268
- Risk IDs: RISK-SF-268, RISK-SF-269

## Findings

### 1. Pattern 1.12 — Mass Assignment via Client-Controlled Fields + Cross-User Case Access: `c.CaseController.getCaseDetails` (HAR Primary)

**HAR evidence**: Aura action `c.CaseController.getCaseDetails` with `caseId: "001B7DD"`, client-supplied `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`. Response: `state: "SUCCESS"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-37-3629"`.

**Pattern 1.12 (Mass Assignment via Object Fields)**: the `fields` parameter is client-controlled — the attacker specifies which Salesforce fields to retrieve, including sensitive custom fields (`InternalNotes__c`, `SensitiveData__c`). This is mass assignment: the client dictates the field set returned by the server. Combined with the BOLA (cross-user `caseId` substitution), the attacker can exfiltrate any field on any Case record in the org.

Section 7.0 — `Case OWD: Private` — users should only access their own Case records. The controller runs `without sharing` (Section 4.0, RISK-SF-268), bypassing OWD=Private. SOQL filters only by `caseId` — missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` (RISK-SF-269).

**Travel / GDS impact**: Case records represent travel support tickets, passenger booking disputes, or airline complaint cases. SSN exposure (`SensitiveData__c: "SSN: 000-37-3629"`) from cross-org Case access enables identity theft of travelers. Client-controlled `fields` parameter allows additional field exfiltration beyond what the application UI would normally expose.

## Reproduction

**Step 1 — Capture baseline Aura request:**

Intercept a legitimate Aura request via Burp Suite or DevTools. Identify `c.CaseController.getCaseDetails` in the `message` body. Record your own `caseId`.

**Step 2 — Substitute victim `caseId` with client-controlled fields (primary HAR attack):**

```
POST https://fbceb7dd.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DFBCEB7DD!ARfbceb7dd...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DFBCEB7DD!ARfbceb7dd...

message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"001B7DD","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure: `state: "ERROR"` / INSUFFICIENT_ACCESS / empty `records`.  
Expected vulnerable: `state: "SUCCESS"` with `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-37-3629"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.

**Step 3 — Mass assignment: request additional sensitive fields:**

```
message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN",
"params":{"caseId":"001B7DD","fields":["Id","Name","OwnerId","SensitiveData__c","InternalNotes__c","AccountId","IsDeleted"]}}]}
```

Expected vulnerable: Server returns all client-requested fields — attacker controls the data exfiltration scope.

## Evidence

- **HAR**: `c.CaseController.getCaseDetails` with `caseId: "001B7DD"`, client-supplied fields → `SUCCESS` → `SensitiveData__c: "SSN: 000-37-3629"`, `OwnerId: "005VICTIM"`.
- **Section 4.0**: Apex controller declared `public class CaseController` (no `with sharing`) — RISK-SF-268.
- **Section 4.0**: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` — RISK-SF-269.
- **Section 7.0**: `Case OWD: Private` — sharing rules bypassed by `without sharing`.
- **HAR params**: client-supplied `fields` array — mass assignment vector.

## Remediation

1. **Add `with sharing` to Apex class** (RISK-SF-268):
   ```apex
   public with sharing class CaseController { ... }
   ```
2. **Add ownership filter to SOQL** (RISK-SF-269):
   ```apex
   WHERE Id = :caseId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Whitelist allowed fields server-side**: never accept client-supplied field list — hardcode the permitted SELECT fields in Apex.
4. **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
5. **Regression test**: Apex test authenticates as User A, requests User B's `caseId` — assert `INSUFFICIENT_ACCESS` or empty `records`.

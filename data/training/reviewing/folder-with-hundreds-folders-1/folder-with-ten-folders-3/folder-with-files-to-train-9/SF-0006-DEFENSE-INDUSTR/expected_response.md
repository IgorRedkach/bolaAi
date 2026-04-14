# Expected Response

## System
- **Domain:** Defense / Secure Repository (Salesforce-Integrated)
- **System:** Aegis Vault Secure Repository (Salesforce-Integrated)
- **Example ID:** SF-0006

## Priority Findings

### Finding 1: Defense Salesforce — SOQL Record-Level Access Failure via Aura getTask Exposes Cross-Ownership Classified Task Records (Pattern 9.2)
**Severity:** Critical
**Category:** GraphQL/Salesforce Platform / SOQL and Salesforce Record-Level Access

**Summary:**
Per §4.0 (RISK-SF-006/RISK-SF-007): The `TaskController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check (`AND OwnerId = UserInfo.getUserId()`). Per §5.0 (Pattern 9.2 — SOQL and Salesforce record-level access): the Aura `getTask` action fails to apply Salesforce record-level sharing rules, allowing an attacker to access any task record by ID substitution. An attacker submitted `c.TaskController.getTask` with `taskId: "00186E4"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-42-9443"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Defense, exposure of classified task records containing PII and operational notes constitutes a national security breach.

**Evidence from HAR:**
- Request: `POST https://22f986e4.lightning.force.com/aura`
- Aura action descriptor: `c.TaskController.getTask`
- `aura.token`: `undefined`
- Params: `taskId: "00186E4"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "00186E4"`, `Name: "Victim Task Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-42-9443"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-006 | TaskController declared `without sharing` |
| context.txt §4.0 | RISK-SF-007 | SOQL missing record-level ownership check |
| context.txt §5.0 | Pattern 9.2 | SOQL record-level access failure — Salesforce sharing not enforced |
| HAR request | params.taskId | 00186E4 — victim classified task ID |
| HAR response | SensitiveData__c | SSN: 000-42-9443 (PII) |
| HAR response | OwnerId | 005VICTIM (record-level access bypass confirmed) |

## Steps to Reproduce

### Step 1 — Aura taskId SOQL record-level access bypass (HAR)
```bash
curl -s -X POST 'https://22f986e4.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"00186E4","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns classified defense task record including `SSN: 000-42-9443`. **Secure:** FORBIDDEN — `with sharing`; SOQL includes `AND OwnerId = :UserInfo.getUserId()`; sharing rules enforced.

## Remediation
1. Declare `TaskController` as `with sharing` to enforce Salesforce object-level and record-level security.
2. Add `AND OwnerId = :UserInfo.getUserId()` to the SOQL WHERE clause.
3. Validate `aura.token` as a valid, non-expired Salesforce session.
4. Define a server-side field allowlist; never return `SensitiveData__c` or `InternalNotes__c` without explicit role-based authorization.
5. Apply CJIS/ITAR/DFARS-compliant field-level security in Salesforce org.

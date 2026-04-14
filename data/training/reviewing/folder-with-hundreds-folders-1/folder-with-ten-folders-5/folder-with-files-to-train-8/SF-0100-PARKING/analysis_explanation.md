# Analysis Explanation
**Folder:** SF-0100-PARKING | **Context source:** This folder's context.txt only.
- System: ParkIQ Management API (SF), Parking/Smart City, OWD: Private on Contact
- Host: `3fe7eeb8.lightning.force.com`, token: `00D3FE7EEB8!AR3fe7eeb8...`
- Descriptor (HAR): `c.ContactController.updateContact`, `contactId: "001EEB8"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getContactDetails` but Aura descriptor in §6.0 is `updateContact`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-41-6707`
- Pattern 1.12: Mass assignment via object fields — client-supplied `fields` array enables reading all custom fields including `InternalNotes__c` and `SensitiveData__c` without server-side field restriction; `without sharing` controller bypasses OWD=Private
- §8.0 RISK-SF-100/101: controller without `with sharing`; no ownership check; client-supplied `contactId` directly interpolated
**Consistency Guard:** All values from this folder's context.txt only.

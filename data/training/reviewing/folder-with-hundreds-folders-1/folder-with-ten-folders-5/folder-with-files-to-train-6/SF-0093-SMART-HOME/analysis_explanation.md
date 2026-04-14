# Analysis Explanation
**Folder:** SF-0093-SMART-HOME | **Context source:** This folder's context.txt only.
- System: NeoBuild BAS Platform (SF), Smart Home/Building Automation, OWD: Private on Contract
- Host: `7d510447.lightning.force.com`, token: `00D7D510447!AR7d510447...`
- Descriptor (HAR): `c.ContractController.approveContract`, `contractId: "0010447"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getContractDetails` but Aura descriptor in §6.0 is `approveContract`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-88-9348`
- Pattern 1.12: Mass assignment via object fields — client-supplied `fields` array enables reading all custom fields including `InternalNotes__c` and `SensitiveData__c` without server-side field restriction
**Consistency Guard:** All values from this folder's context.txt only.

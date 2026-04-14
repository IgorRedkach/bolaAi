# Analysis Explanation
**Folder:** SF-0104-SMART-CITY | **Context source:** This folder's context.txt only.
- System: MetroPulse Traffic Orchestration (SF), Smart City/Traffic Management, OWD: Private on Contract
- Host: `afd6c721.lightning.force.com`, token: `00DAFD6C721!ARafd6c721...`
- Descriptor (HAR): `c.ContractController.approveContract`, `contractId: "001C721"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getContractDetails` but Aura descriptor in §6.0 is `approveContract`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-53-4627`
- Pattern 9.2: SOQL and Salesforce record-level access bypass (Platform) — `without sharing` silently bypasses OWD=Private at the SOQL layer; missing `WITH SECURITY_ENFORCED` means Salesforce FLS/CRUD checks are skipped; attacker reads any traffic management Contract record
- §8.0 RISK-SF-104/105: controller without `with sharing`; no ownership check; client-supplied `contractId` directly interpolated
**Consistency Guard:** All values from this folder's context.txt only.

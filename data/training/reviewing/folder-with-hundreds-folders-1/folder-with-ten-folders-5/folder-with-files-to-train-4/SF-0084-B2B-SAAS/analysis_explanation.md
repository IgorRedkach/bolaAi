# Analysis Explanation
**Folder:** SF-0084-B2B-SAAS | **Context source:** This folder's context.txt only.
- System: PipelinePro Sales API, B2B SaaS/CRM, OWD: Private on CustomRecord
- Host: `4d407c1c.lightning.force.com`, token: `00D4D407C1C!AR4d407c1c...`
- Descriptor (HAR): `c.CustomObjectController.getRecord`, `recordId: "0017C1C"`
- **Inconsistency in context.txt:** Apex class in §4.0 is `CustomRecordController` with method `getCustomRecordDetails`, but Aura descriptor in §6.0 is `c.CustomObjectController.getRecord` (different class name and method). HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-25-3750`
- Pattern 10.2: Parameter escalation — attacker substitutes `recordId` to read victim CRM records beyond their own session scope
**Consistency Guard:** All values from this folder's context.txt only.

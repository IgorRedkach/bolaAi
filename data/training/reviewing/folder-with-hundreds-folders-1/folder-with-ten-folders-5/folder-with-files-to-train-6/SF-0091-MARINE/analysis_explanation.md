# Analysis Explanation
**Folder:** SF-0091-MARINE | **Context source:** This folder's context.txt only.
- System: HarborFlow Port API (SF), Marine/Port Logistics, OWD: Private on CustomRecord
- Host: `9458113e.lightning.force.com`, token: `00D9458113E!AR9458113e...`
- Descriptor (HAR): `c.CustomObjectController.getRecord`, `recordId: "001113E"`
- **Inconsistency in context.txt:** Apex class in §4.0 is `CustomRecordController` with method `getCustomRecordDetails`, but Aura descriptor in §6.0 is `c.CustomObjectController.getRecord` (different class name). HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-72-3923`
- Pattern 10.2: Parameter escalation — attacker substitutes `recordId` to read victim port logistics CustomRecords
**Consistency Guard:** All values from this folder's context.txt only.

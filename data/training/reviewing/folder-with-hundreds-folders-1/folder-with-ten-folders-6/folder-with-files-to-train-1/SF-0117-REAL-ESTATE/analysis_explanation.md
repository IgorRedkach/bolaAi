# Analysis Explanation
**Example:** SF-0117-REAL-ESTATE — EstateFlow Property API
**Pattern:** 3.1 — Client-assumed authority (Insecure Design)

---

## Why This Is a Vulnerability

Pattern 3.1 (Insecure Design — Client-assumed authority) captures a fundamental design flaw: the server architecture assumes the client will only request objects within their own authorization boundary. The `c.ContractController.approveContract` descriptor name suggests a lifecycle action (approval), yet the underlying Apex method (`getContractDetails`) reads contract data. More importantly, the design trusts the `contractId` as coming from a legitimate, scoped interaction — in reality, any authenticated user can supply any ID. The `without sharing` declaration removes the Salesforce sharing-rule safety net entirely, making the client-assumed authority the only access control boundary, which an attacker trivially bypasses.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0117.

- **System Name:** EstateFlow Property API (§1.0)
- **Domain:** Real Estate / PropTech
- **Host:** `6bc97668.lightning.force.com` (§6.0 HAR)
- **Session token:** `00D6BC97668!AR6bc97668...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.ContractController.approveContract` (§6.0)
- **Apex class method (§4.0):** `ContractController.getContractDetails`
- **Object type:** Contract (§3.0)
- **Victim record ID:** `0017668` (§6.0 HAR params)
- **Victim SSN:** `000-91-4780` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `ContractController` declared `without sharing`; no ownership check in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex method is `getContractDetails`; §5.0 and §6.0 HAR use `c.ContractController.approveContract`. HAR Aura descriptor is authoritative. The mismatch between a "read" Apex method and an "approve" Aura descriptor is additionally noted as an architectural coupling inconsistency.

## Domain Risk

Real estate and PropTech platforms manage property contract data, buyer/seller PII, financial terms, and conveyancing information. Unauthorized access to `SensitiveData__c` (SSN: `000-91-4780`) and `InternalNotes__c` of Contract records exposes sensitive financial and identity data of parties to property transactions, with potential for fraud, identity theft, or breach of conveyancing confidentiality.

## What the Model Should Learn

- Pattern 3.1 (client-assumed authority) is an architectural/design flaw — the system was designed assuming clients self-scope their requests. This is a category error in authorization design.
- The descriptor name `approveContract` (a write/lifecycle action name) being backed by a read-only SOQL is a design inconsistency that makes security review harder.
- `without sharing` combined with no ownership check creates a total bypass of Salesforce record-level security.
- Correct design: server must always derive authorization from the authenticated session, never from client-supplied record identifiers alone.

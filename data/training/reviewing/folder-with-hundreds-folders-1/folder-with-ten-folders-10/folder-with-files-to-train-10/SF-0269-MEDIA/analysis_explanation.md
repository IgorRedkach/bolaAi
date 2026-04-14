# Analysis Explanation — SF-0269-MEDIA

## What was wrong

### 1. Wrong controller action, parameter, and object type throughout

Original response used `c.AccountController.getAccounts` with `accountId` parameter on an `Account` object. HAR clearly shows `c.TaskController.getTask` with `taskId` parameter on a `Task` object. Section 4.0 confirms `TaskController`. Fixed throughout.

### 2. Generic org host used

Original Step 3 used `<ORG_ID>.lightning.force.com`. HAR shows `11682a04.lightning.force.com`. Fixed.

### 3. Pattern 2.1 (functional pivot BAC) not explained

Original response described a simple BOLA read without explaining Pattern 2.1 (Functional Pivot — BAC). Pattern 2.1 involves pivoting into functional scope not intended for the attacker: both horizontal pivot (accessing other users' Task records) and functional pivot (exercising Task management operations beyond the attacker's authorized scope). Added explicit explanation of both pivot types and their relationship to BAC.

### 4. SSN from HAR not specifically referenced

HAR response shows `SensitiveData__c: "SSN: 000-24-9729"`. Added specific reference.

### 5. Remediation used wrong controller name

Fixed `AccountController` → `TaskController`, `accountId` → `taskId`.

### 6. Method name inconsistency noted

Section 4.0 names the method `getTaskDetails` but HAR and Section 5.0 use `getTask`. HAR is authoritative — `getTask` is the correct production action name.

## Domain context

StreamCore is a Media / Content Delivery (VOD) platform. Task records represent content review workflows, streaming infrastructure management tasks, or content rights management activities. Cross-user Task access (Pattern 2.1 horizontal pivot) exposes content pipeline internals, editorial review decisions, and SSN data from content manager profiles. Functional pivot allows an attacker to exercise content management operations belonging to other team members.

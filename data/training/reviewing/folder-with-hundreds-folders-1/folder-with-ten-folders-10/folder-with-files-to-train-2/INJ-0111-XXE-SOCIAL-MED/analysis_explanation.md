# Analysis Explanation — INJ-0111-XXE-SOCIAL-MED

## What was wrong

### 1. Wrong endpoint and parameter throughout

Original response used `/api/v1/users?search=`. Section 3.0 and HAR both specify `/api/v3/users?id=`. Fixed all steps.

### 2. Generic host URL in Steps 3/4

Steps 3 and 4 used `api.example.com`. Fixed to `api.horizon-social-.example.com`.

### 3. XXE mechanics completely absent — SQLi description used for XXE

Original response described XXE as "evaluates to true for all rows" — this is an SQLi description. XXE does not work by evaluating SQL predicates. XXE (XML External Entity Injection) works by:
1. Injecting an XML DOCTYPE that defines an external entity referencing a local file or network URL
2. The XML parser resolves the entity, reading the file content
3. The content is included in the parsed result and returned to the attacker

Added proper XXE steps:
- Step 2: `/etc/passwd` file read via external entity
- Step 3: SSRF via AWS instance metadata endpoint (cloud credential theft)
- Step 4: environment variable file read for application secrets

### 4. SSRF via XXE not demonstrated

XXE's most dangerous escalation path in cloud environments is SSRF to `169.254.169.254` (AWS EC2 metadata) to steal IAM role credentials. Added as Step 3.

### 5. Context inconsistency acknowledged

Section 2.0 declares XML parser but Section 3.0 shows SQL concatenation. Both vectors documented and demonstrated.

## Domain context

Horizon Social Graph API is a Social Media / Identity Graph platform. `users` table contains identity graph records (social connections, authentication data). XXE SSRF to cloud metadata enables full AWS account compromise. Admin credential theft enables identity graph takeover — exposing all user social connections and PII at scale.

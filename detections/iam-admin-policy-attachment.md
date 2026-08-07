# Detection: IAM Administrator Policy Attachment

## Overview

Detects when the AWS-managed `AdministratorAccess` policy is attached to an IAM user.

Attaching AdministratorAccess grants extensive permissions across the AWS account. An attacker with permission to modify IAM policies could use this technique to escalate the privileges of a compromised or attacker-controlled identity.

---

## Severity

High

---

## Data Source

AWS CloudTrail

Sourcetype:

`aws:cloudtrail`

---

## CloudTrail Event

`AttachUserPolicy`

---

## Detection Logic

```spl
index=* sourcetype="aws:cloudtrail"
eventName="AttachUserPolicy"
requestParameters.policyArn="*AdministratorAccess"
| table _time
        eventName
        userIdentity.arn
        sourceIPAddress
        requestParameters.userName
        requestParameters.policyArn
| sort - _time
```

---

## Attack Simulation

A controlled test was performed by temporarily attaching the AWS-managed `AdministratorAccess` policy to the test IAM user:

```bash
aws iam attach-user-policy \
  --user-name splunk-detection-test \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

The policy was immediately removed after generating the required CloudTrail telemetry:

```bash
aws iam detach-user-policy \
  --user-name splunk-detection-test \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

The elevated permissions were not used during the simulation.

---

## Expected Result

CloudTrail records an `AttachUserPolicy` event where:

- `requestParameters.userName` identifies the target IAM user.
- `requestParameters.policyArn` identifies `AdministratorAccess`.
- `userIdentity.arn` identifies the identity that performed the change.
- `sourceIPAddress` identifies the source of the request.

The event flows through:

AWS CloudTrail → S3 → SQS → Splunk

The Splunk detection identifies the AdministratorAccess policy attachment.

---

## Investigation

When this detection triggers, investigate:

1. Which identity attached the policy?
2. Which IAM user received AdministratorAccess?
3. Was the privilege change authorized?
4. What source IP address initiated the request?
5. Was the target IAM user recently created?
6. Were access keys recently created for the target user?
7. What actions did the newly privileged identity perform afterward?
8. Was the AdministratorAccess policy subsequently removed?

Particular attention should be given to sequences such as:

`CreateUser → CreateAccessKey → AttachUserPolicy`

which may indicate an attempt to establish a new privileged identity.

---

## Potential False Positives

Authorized administrators or infrastructure automation may legitimately attach AdministratorAccess during account administration or testing.

Production environments should establish expected administrative identities and change-management processes to distinguish authorized changes from suspicious privilege escalation.

---

## Remediation

If the policy attachment is unauthorized:

1. Detach the AdministratorAccess policy immediately.
2. Disable credentials associated with the affected IAM identity.
3. Review CloudTrail activity performed after privilege escalation.
4. Investigate the identity responsible for attaching the policy.
5. Rotate potentially compromised credentials.
6. Review other IAM users and roles for unauthorized permission changes.

---

## Evidence

See:

`screenshots/iam-admin-policy-attachment.png`
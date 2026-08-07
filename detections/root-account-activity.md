# Detection: AWS Root Account Activity

## Overview

Detects AWS API activity performed using the AWS account root user.

The root user has unrestricted access to the AWS account and should not be used for routine administrative tasks. Root activity can indicate account misuse, credential compromise, or unauthorized administrative activity.

Because of the level of access associated with the root account, unexpected root activity should be investigated immediately.

---

## Severity

**Critical**

---

## Data Source

AWS CloudTrail

Sourcetype:

`aws:cloudtrail`

---

## Detection Condition

CloudTrail events where:

```text
userIdentity.type = Root
```

Unlike detections based on a specific API operation, this detection monitors any CloudTrail activity performed by the AWS root identity.

---

## Detection Logic

```spl
index=* sourcetype="aws:cloudtrail"
userIdentity.type="Root"
| table _time
        eventName
        eventSource
        sourceIPAddress
        userAgent
        userIdentity.type
| sort - _time
```

---

## Security Significance

The AWS root user has unrestricted access to the account.

An attacker who obtains root credentials could potentially:

- Modify IAM identities and permissions.
- Create or delete infrastructure.
- Disable security controls.
- Modify CloudTrail configuration.
- Access sensitive AWS resources.
- Change account-level settings.
- Establish additional persistence mechanisms.

Root credentials should therefore be protected and their use minimized.

---

## Attack Scenario

An attacker obtains credentials associated with the AWS root account.

The attacker then performs AWS administrative activity using the compromised root identity.

Example:

```text
Root Credentials Compromised
            ↓
      Root Authentication
            ↓
       AWS API Activity
            ↓
       CloudTrail Event
            ↓
userIdentity.type = Root
            ↓
       Critical Alert
```

Because legitimate root activity should be rare, any root API activity is considered high priority.

---

## Detection Validation

No new root activity was intentionally generated for this test.

Instead, existing CloudTrail events associated with previous root account activity were used to validate the detection.

This avoids unnecessarily using the AWS root account solely for security testing.

The historical events were successfully:

1. Recorded by AWS CloudTrail.
2. Delivered to the CloudTrail S3 bucket.
3. Processed through the SQS ingestion queue.
4. Ingested into Splunk.
5. Identified using the root activity detection query.

---

## Expected Result

When root activity occurs, CloudTrail records:

```text
userIdentity.type = Root
```

The event follows the detection pipeline:

```text
AWS Root Activity
        ↓
AWS CloudTrail
        ↓
S3 Log Bucket
        ↓
SQS Notification
        ↓
Splunk
        ↓
Root Activity Detection
        ↓
Critical Alert
```

---

## Investigation

When this detection triggers, investigate:

1. What AWS action was performed?
2. When did the activity occur?
3. What source IP address initiated the request?
4. What user agent or tool was used?
5. Was root account usage expected and authorized?
6. What activity occurred immediately before and after the root event?
7. Were IAM users, roles, policies, or access keys modified?
8. Were security controls such as CloudTrail changed?
9. Were sensitive AWS resources accessed or modified?
10. Is there evidence of additional suspicious activity from the same source IP?

The surrounding CloudTrail timeline should be reviewed to determine whether the root event is part of a larger sequence of suspicious activity.

---

## Potential False Positives

Some AWS account-level operations legitimately require the root user.

Therefore, root activity does not automatically indicate compromise.

However, because root usage should be rare, every occurrence should be validated against expected administrative activity.

Routine AWS administration should use IAM users or roles with appropriate least-privilege permissions instead of the root identity.

---

## Remediation

If root activity is unauthorized:

1. Secure the AWS root account immediately.
2. Change the root account password.
3. Review and verify MFA configuration.
4. Review CloudTrail for additional root activity.
5. Investigate the source IP associated with the activity.
6. Review IAM users, roles, policies, and access keys for unauthorized changes.
7. Disable or remove unauthorized credentials.
8. Review sensitive AWS resources for unexpected modifications.
9. Verify that security logging and monitoring remain enabled.

---

## Splunk Alert

Recommended alert configuration:

```text
Alert Name:
AWS - Root Account Activity Detected

Severity:
Critical

Alert Type:
Scheduled

Schedule:
Every 5 minutes

Search Window:
Last 10 minutes

Trigger:
Number of Results > 0
```

The overlapping search window helps account for CloudTrail ingestion latency.

---

## Evidence

Screenshot of historical root activity detected in Splunk:

`screenshots/root-account-actvity.png`

The screenshot demonstrates that the pipeline successfully identifies CloudTrail events associated with the AWS root identity.

---

## Security Recommendation

The AWS root account should be reserved for operations that specifically require root access.

Routine administration should be performed through dedicated IAM identities or roles using least-privilege permissions.

Root account protections should include:

- Strong authentication credentials.
- MFA enabled on the root user.
- No root access keys.
- Continuous monitoring of root activity.
- Immediate investigation of unexpected root usage.

---

## Detection Status

**Validated**

Historical root account activity was successfully detected by the AWS CloudTrail → S3 → SQS → Splunk detection pipeline.

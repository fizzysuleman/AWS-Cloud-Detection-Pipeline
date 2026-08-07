# Detection: CloudTrail Logging Disabled

## Overview

Detects when logging is disabled for an AWS CloudTrail trail using the `StopLogging` API operation.

CloudTrail provides audit visibility into AWS API activity. An attacker who gains sufficient privileges may attempt to disable CloudTrail logging to reduce visibility into subsequent malicious activity and interfere with security monitoring.

Disabling CloudTrail should therefore be treated as a high-priority security event.

---

## Severity

**Critical**

---

## Data Source

AWS CloudTrail

Sourcetype:

`aws:cloudtrail`

---

## CloudTrail Event

`StopLogging`

---

## Detection Logic

```spl
index=* sourcetype="aws:cloudtrail"
eventName="StopLogging"
| table _time
        eventName
        userIdentity.arn
        sourceIPAddress
        userAgent
        requestParameters.name
| sort - _time
```

The detection identifies any successful invocation of the CloudTrail `StopLogging` API operation.

---

## Attack Scenario

An attacker obtains access to an AWS identity with permission to modify CloudTrail configuration.

The attacker attempts to reduce security visibility by disabling an active CloudTrail trail.

Example attack sequence:

```text
Compromised AWS Identity
          ↓
      StopLogging
          ↓
 CloudTrail disabled
          ↓
 Reduced audit visibility
          ↓
Potential malicious activity
```

Stopping CloudTrail may indicate an attempt to interfere with logging or evade security monitoring.

---

## Attack Simulation

The detection was tested against the project's CloudTrail trail:

`cloud-security-detection-trail`

Logging was disabled using the AWS CLI:

```bash
aws cloudtrail stop-logging \
  --name cloud-security-detection-trail
```

This generated a CloudTrail event with:

```text
eventName = StopLogging
```

The trail was subsequently re-enabled:

```bash
aws cloudtrail start-logging \
  --name cloud-security-detection-trail
```

Logging status was verified using:

```bash
aws cloudtrail get-trail-status \
  --name cloud-security-detection-trail
```

The expected result after recovery is:

```text
"IsLogging": true
```

---

## Expected Result

CloudTrail records the `StopLogging` API operation.

The security event flows through the detection pipeline:

```text
StopLogging API Call
        ↓
AWS CloudTrail
        ↓
S3 Log Bucket
        ↓
SQS Notification
        ↓
Splunk
        ↓
StopLogging Detection
        ↓
Critical Alert
```

Splunk identifies the event using the detection query.

---

## Investigation

When this detection triggers, the following questions should be investigated:

1. Which AWS identity stopped CloudTrail logging?
2. What source IP address initiated the request?
3. What user agent or tool was used?
4. Which CloudTrail trail was affected?
5. Was disabling CloudTrail an approved administrative action?
6. What AWS activity occurred immediately before `StopLogging`?
7. How long was CloudTrail logging disabled?
8. Was `StartLogging` subsequently called?
9. Were IAM permissions modified before logging was disabled?
10. Are there signs that the responsible credentials were compromised?

Special attention should be given to suspicious sequences such as:

```text
CreateUser
    ↓
CreateAccessKey
    ↓
AttachUserPolicy
    ↓
StopLogging
```

Such a sequence could indicate privilege escalation followed by an attempt to evade detection.

---

## Potential False Positives

Legitimate administrators may temporarily disable CloudTrail during troubleshooting, testing, or configuration changes.

However, disabling security logging should be uncommon in production environments.

All occurrences of `StopLogging` should therefore be investigated and validated against approved administrative activity.

---

## Remediation

If CloudTrail logging was disabled without authorization:

1. Re-enable CloudTrail logging immediately.
2. Identify the IAM identity responsible for the action.
3. Review the permissions associated with that identity.
4. Disable or rotate potentially compromised credentials.
5. Investigate AWS activity surrounding the `StopLogging` event.
6. Review IAM activity for privilege escalation or persistence.
7. Restrict `cloudtrail:StopLogging` to tightly controlled administrative identities.
8. Consider centralized or organization-level CloudTrail logging for production environments.

---

## Detection Validation

During testing, the `StopLogging` event was successfully:

1. Generated using the AWS CLI.
2. Recorded by AWS CloudTrail.
3. Delivered to the CloudTrail S3 bucket.
4. Processed through the SQS ingestion queue.
5. Ingested by Splunk.
6. Identified using the Splunk detection query.

The event was not immediately visible in Splunk during initial testing because the CloudTrail → S3 → SQS ingestion pipeline introduces delivery latency.

After allowing sufficient time for log delivery, the `StopLogging` event was successfully detected.

---

## Splunk Alert

The detection can be configured as a scheduled Splunk alert.

Recommended configuration:

```text
Alert Name:
AWS - CloudTrail Logging Disabled

Severity:
Critical

Schedule:
Every 5 minutes

Search Window:
Last 10 minutes

Trigger:
Number of Results > 0
```

Using a search window larger than the execution interval provides overlap to account for CloudTrail delivery latency.

---

## Evidence

Screenshot of the successfully detected `StopLogging` event:

`screenshots/cloudtrail-stop-logging.png`

The screenshot demonstrates the complete detection path from the simulated AWS API operation to the event appearing in Splunk.

---

## Security Significance

CloudTrail is a critical source of AWS security telemetry.

An unauthorized attempt to disable CloudTrail may indicate that an attacker is attempting to reduce visibility before performing additional malicious activity.

For this reason, `StopLogging` should be treated as a **Critical severity detection** and investigated immediately.
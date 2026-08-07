# Detection: IAM Access Key Creation

## Overview

Detects the creation of a new AWS IAM access key.

Access keys provide long-term programmatic access to AWS. An attacker
who compromises a privileged identity may create additional access keys
to establish persistent access to the environment.

---

## Severity

Medium

---

## Data Source

AWS CloudTrail

Sourcetype:

aws:cloudtrail

---

## CloudTrail Event

CreateAccessKey

---

## Detection Logic

```spl
index=* sourcetype="aws:cloudtrail"
eventName="CreateAccessKey"
| table _time
        userIdentity.arn
        sourceIPAddress
        userAgent
        requestParameters.userName
        responseElements.accessKey.accessKeyId
| sort - _time
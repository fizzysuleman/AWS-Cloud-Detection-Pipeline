# ---------------------------------------------------------
# SQS Queue for CloudTrail → Splunk Notifications
# ---------------------------------------------------------

resource "aws_sqs_queue" "cloudtrail_splunk" {
  name = "cloudtrail-splunk-queue"

  message_retention_seconds = 86400

  tags = {
    Name      = "CloudTrail Splunk Queue"
    Project   = var.project_name
    ManagedBy = "Terraform"
  }
}

data "aws_iam_policy_document" "sqs_allow_s3" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = [
      "sqs:SendMessage"
    ]

    resources = [
      aws_sqs_queue.cloudtrail_splunk.arn
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"

      values = [
        aws_s3_bucket.cloudtrail_logs.arn
      ]
    }
  }
}

resource "aws_sqs_queue_policy" "cloudtrail_splunk" {
  queue_url = aws_sqs_queue.cloudtrail_splunk.id
  policy    = data.aws_iam_policy_document.sqs_allow_s3.json
}

resource "aws_s3_bucket_notification" "cloudtrail_to_sqs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  queue {
    queue_arn = aws_sqs_queue.cloudtrail_splunk.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [
    aws_sqs_queue_policy.cloudtrail_splunk
  ]
}
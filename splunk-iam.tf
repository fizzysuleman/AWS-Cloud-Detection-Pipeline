# ---------------------------------------------------------
# Splunk SIEM User
# ---------------------------------------------------------

resource "aws_iam_user" "splunk_siem" {
  name = "splunk-siem-reader"

  tags = {
    Project   = var.project_name
    ManagedBy = "Terraform"
  }
}

# ---------------------------------------------------------
# Splunk S3 Read Permissions and SQS Permissions
# ---------------------------------------------------------

data "aws_iam_policy_document" "splunk_s3_read" {

  statement {
    effect = "Allow"

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]

    resources = [
      aws_s3_bucket.cloudtrail_logs.arn
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "s3:GetObject"
    ]

    resources = [
      "${aws_s3_bucket.cloudtrail_logs.arn}/*"
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl"
    ]

    resources = [
      aws_sqs_queue.cloudtrail_splunk.arn
    ]
  }

  statement {
    effect = "Allow"
    
    actions = [
        "sqs:ListQueues"
    ]

    resources = ["*"]
    }
}

resource "aws_iam_user_policy" "splunk_s3_read" {
  name   = "splunk-cloudtrail-read"
  user   = aws_iam_user.splunk_siem.name
  policy = data.aws_iam_policy_document.splunk_s3_read.json
}
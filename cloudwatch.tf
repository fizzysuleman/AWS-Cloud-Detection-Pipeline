# ---------------------------------------------------------
# CloudWatch Log Group for CloudTrail
# ---------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "/aws/cloudtrail/security-detection"
  retention_in_days = 30

  tags = {
    Name      = "CloudTrail Security Logs"
    Project   = var.project_name
    ManagedBy = "Terraform"
  }
}

# ---------------------------------------------------------
# IAM Role assumed by CloudTrail
# ---------------------------------------------------------

data "aws_iam_policy_document" "cloudtrail_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name               = "cloudtrail-cloudwatch-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role.json

  tags = {
    Project   = var.project_name
    ManagedBy = "Terraform"
  }
}


data "aws_iam_policy_document" "cloudtrail_cloudwatch_permissions" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name   = "cloudtrail-cloudwatch-policy"
  role   = aws_iam_role.cloudtrail_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_permissions.json
}
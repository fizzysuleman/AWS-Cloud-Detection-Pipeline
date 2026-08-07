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
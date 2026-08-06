variable "aws_region" {
  description = "AWS region used for the detection pipeline"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for AWS resource naming"
  type        = string
  default     = "aws-cloud-detection-pipeline"
}
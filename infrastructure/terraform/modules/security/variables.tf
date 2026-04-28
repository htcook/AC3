variable "environment" { type = string }
variable "project_name" { type = string }
variable "aws_region" { type = string }
variable "account_id" { type = string }
variable "enable_guardduty" { type = bool }
variable "enable_security_hub" { type = bool }
variable "enable_cloudtrail" { type = bool }
variable "enable_aws_config" { type = bool }

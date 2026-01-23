############################################
# VARIABLES
############################################

variable "aws_region" {
  type        = string
  description = "AWS region to deploy resources into"
  default     = "us-east-1"
}

variable "telegram_bot_token" {
  type        = string
  sensitive   = true
  description = "Telegram Bot Token"
}

variable "openai_api_key" {
  type        = string
  sensitive   = true
  description = "OpenAI API Key (optional)"
  default     = ""
}

variable "gemini_api_key" {
  type        = string
  sensitive   = true
  description = "Google Gemini API Key (optional)"
  default     = ""
}

variable "ddb_table_name" {
  type        = string
  default     = "telegram-bot-messages"
  description = "DynamoDB table name for storing Telegram updates"
}

variable "s3_bucket_name" {
  type        = string
  # IMPORTANT: must be globally unique across ALL AWS accounts
  default     = "telegram-bot-v2"
  description = "S3 bucket name for storing uploaded files"
}

variable "environment" {
  type        = string
  default     = "dev"
  description = "Environment name (dev, staging, prod)"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# UPDATED: Support for multiple email addresses
variable "alarm_emails" {
  type        = list(string)
  description = "List of email addresses to receive CloudWatch alarm notifications"
  default     = []
  
  validation {
    condition = alltrue([
      for email in var.alarm_emails : 
      can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All emails must be valid email addresses."
  }
}
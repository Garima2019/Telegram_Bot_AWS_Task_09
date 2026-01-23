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
  default     = "telegram-bot-files-v2-CHANGE-ME"
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

# NEW: Email for CloudWatch alarm notifications
variable "alarm_email" {
  type        = string
  description = "Email address to receive CloudWatch alarm notifications (optional)"
  default     = ""
  
  validation {
    condition     = var.alarm_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.alarm_email))
    error_message = "Must be a valid email address or empty string."
  }
}

# ============================================
# Add groq_api_key variable
# ============================================

# Add this new variable to variables.tf:

variable "groq_api_key" {
  type        = string
  sensitive   = true
  description = "Groq API Key (optional)"
  default     = ""
}

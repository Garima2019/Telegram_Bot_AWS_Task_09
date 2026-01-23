############################################
# CLOUDWATCH OBSERVABILITY
############################################

# ========= LOG GROUPS WITH RETENTION =========

# Lambda Function Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.telegram_lambda.function_name}"
  retention_in_days = 14

  tags = {
    Name        = "Telegram Bot Lambda Logs"
    Environment = var.environment
  }
}

# API Gateway Log Group
resource "aws_cloudwatch_log_group" "apigw_logs" {
  name              = "/aws/apigateway/telegram-http-api-v2"
  retention_in_days = 7

  tags = {
    Name        = "Telegram Bot API Gateway Logs"
    Environment = var.environment
  }
}

# ========= METRIC FILTERS =========

# Error Detection Metric Filter
resource "aws_cloudwatch_log_metric_filter" "lambda_errors" {
  name           = "telegram-bot-lambda-errors"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  
  # Pattern matches structured logs with level=ERROR
  pattern = "{ $.level = \"ERROR\" }"

  metric_transformation {
    name      = "LambdaErrorCount"
    namespace = "TelegramBot/Lambda"
    value     = "1"
    default_value = 0
    unit      = "Count"
  }
}

# Success Metric Filter (for monitoring healthy requests)
resource "aws_cloudwatch_log_metric_filter" "lambda_success" {
  name           = "telegram-bot-lambda-success"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  
  # Pattern matches structured logs with level=INFO and outcome=success
  pattern = "{ $.level = \"INFO\" && $.outcome = \"success\" }"

  metric_transformation {
    name      = "LambdaSuccessCount"
    namespace = "TelegramBot/Lambda"
    value     = "1"
    default_value = 0
    unit      = "Count"
  }
}

# Message Processing Metric Filter
resource "aws_cloudwatch_log_metric_filter" "messages_processed" {
  name           = "telegram-bot-messages-processed"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  
  # Pattern matches when messages are saved to DynamoDB
  pattern = "{ $.message = \"Message saved to DynamoDB\" }"

  metric_transformation {
    name      = "MessagesProcessed"
    namespace = "TelegramBot/Lambda"
    value     = "1"
    default_value = 0
    unit      = "Count"
  }
}

# File Upload Metric Filter
resource "aws_cloudwatch_log_metric_filter" "files_uploaded" {
  name           = "telegram-bot-files-uploaded"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  
  # Pattern matches successful S3 uploads
  pattern = "{ $.message = \"File uploaded to S3\" }"

  metric_transformation {
    name      = "FilesUploaded"
    namespace = "TelegramBot/Lambda"
    value     = "1"
    default_value = 0
    unit      = "Count"
  }
}

# ========= SNS TOPIC FOR ALARMS =========

resource "aws_sns_topic" "cloudwatch_alarms" {
  name = "telegram-bot-cloudwatch-alarms"

  tags = {
    Name        = "Telegram Bot CloudWatch Alarms"
    Environment = var.environment
  }
}

# Email subscriptions for alarms (supports multiple emails - each requires confirmation)
resource "aws_sns_topic_subscription" "alarm_emails" {
  for_each  = toset(var.alarm_emails)
  topic_arn = aws_sns_topic.cloudwatch_alarms.arn
  protocol  = "email"
  endpoint  = each.value
}

# ========= CLOUDWATCH ALARMS =========

# Error Rate Alarm
resource "aws_cloudwatch_metric_alarm" "lambda_error_alarm" {
  alarm_name          = "telegram-bot-lambda-errors"
  alarm_description   = "Alert when Lambda function encounters errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  
  # Evaluation period: 1 error within 5 minutes triggers alarm
  evaluation_periods  = 1
  threshold           = 1
  
  # Check every 5 minutes
  period              = 300
  
  metric_name         = "LambdaErrorCount"
  namespace           = "TelegramBot/Lambda"
  statistic           = "Sum"
  
  # Treat missing data as good (no errors)
  treat_missing_data  = "notBreaching"
  
  # Send notification to SNS
  alarm_actions       = [aws_sns_topic.cloudwatch_alarms.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_alarms.arn]

  tags = {
    Name        = "Telegram Bot Lambda Error Alarm"
    Environment = var.environment
    Severity    = "High"
  }
}

# High Error Rate Alarm (stricter threshold)
resource "aws_cloudwatch_metric_alarm" "lambda_high_error_rate" {
  alarm_name          = "telegram-bot-lambda-high-error-rate"
  alarm_description   = "Alert when error rate is high (5+ errors in 5 minutes)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  
  evaluation_periods  = 1
  threshold           = 5
  period              = 300
  
  metric_name         = "LambdaErrorCount"
  namespace           = "TelegramBot/Lambda"
  statistic           = "Sum"
  
  treat_missing_data  = "notBreaching"
  
  alarm_actions       = [aws_sns_topic.cloudwatch_alarms.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_alarms.arn]

  tags = {
    Name        = "Telegram Bot Lambda High Error Rate"
    Environment = var.environment
    Severity    = "Critical"
  }
}

# Lambda Duration Alarm (performance monitoring)
resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "telegram-bot-lambda-duration"
  alarm_description   = "Alert when Lambda execution time is consistently high"
  comparison_operator = "GreaterThanThreshold"
  
  # Alert if average duration > 30 seconds for 2 consecutive 5-min periods
  evaluation_periods  = 2
  threshold           = 30000  # milliseconds
  period              = 300
  
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  statistic           = "Average"
  
  dimensions = {
    FunctionName = aws_lambda_function.telegram_lambda.function_name
  }
  
  treat_missing_data  = "notBreaching"
  
  alarm_actions       = [aws_sns_topic.cloudwatch_alarms.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_alarms.arn]

  tags = {
    Name        = "Telegram Bot Lambda Duration"
    Environment = var.environment
    Severity    = "Medium"
  }
}

# Lambda Throttling Alarm
resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name          = "telegram-bot-lambda-throttles"
  alarm_description   = "Alert when Lambda function is being throttled"
  comparison_operator = "GreaterThanThreshold"
  
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  statistic           = "Sum"
  
  dimensions = {
    FunctionName = aws_lambda_function.telegram_lambda.function_name
  }
  
  treat_missing_data  = "notBreaching"
  
  alarm_actions       = [aws_sns_topic.cloudwatch_alarms.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_alarms.arn]

  tags = {
    Name        = "Telegram Bot Lambda Throttles"
    Environment = var.environment
    Severity    = "High"
  }
}

# DynamoDB Errors Alarm
resource "aws_cloudwatch_metric_alarm" "dynamodb_errors" {
  alarm_name          = "telegram-bot-dynamodb-errors"
  alarm_description   = "Alert when DynamoDB operations fail"
  comparison_operator = "GreaterThanThreshold"
  
  evaluation_periods  = 1
  threshold           = 5
  period              = 300
  
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  statistic           = "Sum"
  
  dimensions = {
    TableName = aws_dynamodb_table.telegram_messages.name
  }
  
  treat_missing_data  = "notBreaching"
  
  alarm_actions       = [aws_sns_topic.cloudwatch_alarms.arn]

  tags = {
    Name        = "Telegram Bot DynamoDB Errors"
    Environment = var.environment
    Severity    = "High"
  }
}

# ========= CLOUDWATCH DASHBOARD =========

resource "aws_cloudwatch_dashboard" "telegram_bot" {
  dashboard_name = "telegram-bot-observability"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["TelegramBot/Lambda", "LambdaErrorCount", { stat = "Sum", label = "Errors" }],
            [".", "LambdaSuccessCount", { stat = "Sum", label = "Success" }],
            [".", "MessagesProcessed", { stat = "Sum", label = "Messages" }],
            [".", "FilesUploaded", { stat = "Sum", label = "Files Uploaded" }]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Bot Activity Overview"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", { stat = "Average", label = "Avg Duration" }],
            ["...", { stat = "Maximum", label = "Max Duration" }]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Lambda Performance"
          yAxis = {
            left = {
              label = "Milliseconds"
              min   = 0
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", { stat = "Sum", label = "Invocations" }],
            [".", "Errors", { stat = "Sum", label = "Lambda Errors" }],
            [".", "Throttles", { stat = "Sum", label = "Throttles" }]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Lambda Metrics"
        }
      },
      {
        type = "log"
        properties = {
          query   = <<-EOT
            SOURCE '${aws_cloudwatch_log_group.lambda_logs.name}'
            | fields @timestamp, level, message, user_id, outcome, error_message
            | filter level = "ERROR"
            | sort @timestamp desc
            | limit 20
          EOT
          region  = var.aws_region
          title   = "Recent Errors"
        }
      }
    ]
  })
}
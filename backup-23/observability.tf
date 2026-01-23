############################################
# OBSERVABILITY.TF
# CloudWatch Logs and Monitoring
############################################

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gateway_logs" {
  name              = "/aws/apigateway/telegram-http-api-v2"
  retention_in_days = 7  # Adjust based on your needs (1, 3, 5, 7, 14, 30, 60, 90, etc.)

  tags = {
    Name        = "Telegram API Gateway Logs"
    Environment = var.environment
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/telegram-bot-lambda-v2"
  retention_in_days = 7

  tags = {
    Name        = "Telegram Lambda Logs"
    Environment = var.environment
  }
}

# API Gateway Stage with Access Logging
resource "aws_apigatewayv2_stage" "prod_with_logging" {
  api_id      = aws_apigatewayv2_api.telegram_api.id
  name        = "prod"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      errorMessage   = "$context.error.message"
      integrationError = "$context.integrationErrorMessage"
    })
  }

  default_route_settings {
    detailed_metrics_enabled = true
    throttling_burst_limit   = 100
    throttling_rate_limit    = 50
  }

  tags = {
    Name        = "Telegram Bot API Stage"
    Environment = var.environment
  }

  depends_on = [aws_cloudwatch_log_group.api_gateway_logs]
}

# CloudWatch Alarms (Optional but recommended)

# Lambda Error Alarm
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count               = var.alarm_email != "" ? 1 : 0
  alarm_name          = "telegram-lambda-errors-v2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors lambda errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.telegram_lambda.function_name
  }

  alarm_actions = [aws_sns_topic.alerts[0].arn]

  tags = {
    Name        = "Lambda Error Alarm"
    Environment = var.environment
  }
}

# Lambda Duration Alarm (Timeout Warning)
resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  count               = var.alarm_email != "" ? 1 : 0
  alarm_name          = "telegram-lambda-duration-v2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "50000"  # 50 seconds (timeout is 60s)
  alarm_description   = "This metric monitors lambda duration approaching timeout"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.telegram_lambda.function_name
  }

  alarm_actions = [aws_sns_topic.alerts[0].arn]

  tags = {
    Name        = "Lambda Duration Alarm"
    Environment = var.environment
  }
}

# API Gateway 4XX Errors
resource "aws_cloudwatch_metric_alarm" "api_4xx_errors" {
  count               = var.alarm_email != "" ? 1 : 0
  alarm_name          = "telegram-api-4xx-errors-v2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "4XXError"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors API Gateway 4xx errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ApiId = aws_apigatewayv2_api.telegram_api.id
  }

  alarm_actions = [aws_sns_topic.alerts[0].arn]

  tags = {
    Name        = "API 4XX Error Alarm"
    Environment = var.environment
  }
}

# API Gateway 5XX Errors
resource "aws_cloudwatch_metric_alarm" "api_5xx_errors" {
  count               = var.alarm_email != "" ? 1 : 0
  alarm_name          = "telegram-api-5xx-errors-v2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "5XXError"
  namespace           = "AWS/ApiGateway"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors API Gateway 5xx errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ApiId = aws_apigatewayv2_api.telegram_api.id
  }

  alarm_actions = [aws_sns_topic.alerts[0].arn]

  tags = {
    Name        = "API 5XX Error Alarm"
    Environment = var.environment
  }
}

# SNS Topic for Alarms
resource "aws_sns_topic" "alerts" {
  count = var.alarm_email != "" ? 1 : 0
  name  = "telegram-bot-alerts-v2"

  tags = {
    Name        = "Telegram Bot Alerts"
    Environment = var.environment
  }
}

# SNS Topic Subscription
resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# DynamoDB Alarms

# Read Capacity Alarm (for Pay-per-request, monitors read throttles)
resource "aws_cloudwatch_metric_alarm" "dynamodb_read_throttle" {
  count               = var.alarm_email != "" ? 1 : 0
  alarm_name          = "telegram-dynamodb-read-throttle-v2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ReadThrottleEvents"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors DynamoDB read throttle events"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.telegram_messages.name
  }

  alarm_actions = [aws_sns_topic.alerts[0].arn]

  tags = {
    Name        = "DynamoDB Read Throttle Alarm"
    Environment = var.environment
  }
}

# Write Capacity Alarm
resource "aws_cloudwatch_metric_alarm" "dynamodb_write_throttle" {
  count               = var.alarm_email != "" ? 1 : 0
  alarm_name          = "telegram-dynamodb-write-throttle-v2"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "WriteThrottleEvents"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors DynamoDB write throttle events"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.telegram_messages.name
  }

  alarm_actions = [aws_sns_topic.alerts[0].arn]

  tags = {
    Name        = "DynamoDB Write Throttle Alarm"
    Environment = var.environment
  }
}
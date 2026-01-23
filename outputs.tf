############################################
# OUTPUTS
############################################

output "webhook_url" {
  description = "Telegram webhook URL to configure in your bot"
  value       = "${aws_apigatewayv2_stage.prod.invoke_url}/webhook"
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket storing files"
  value       = aws_s3_bucket.telegram_files.id
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table"
  value       = aws_dynamodb_table.telegram_messages.name
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.telegram_lambda.function_name
}

output "api_gateway_id" {
  description = "ID of the API Gateway"
  value       = aws_apigatewayv2_api.telegram_api.id
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_role.arn
}

# Observability outputs
output "cloudwatch_log_group" {
  description = "CloudWatch log group name for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "error_alarm_name" {
  description = "Name of the error detection alarm"
  value       = aws_cloudwatch_metric_alarm.lambda_error_alarm.alarm_name
}

output "dashboard_url" {
  description = "URL to CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.telegram_bot.dashboard_name}"
}

output "sns_topic_arn" {
  description = "ARN of SNS topic for alarm notifications"
  value       = aws_sns_topic.cloudwatch_alarms.arn
}
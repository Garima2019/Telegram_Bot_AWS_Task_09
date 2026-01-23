############################################
# OUTPUTS
############################################

output "api_endpoint" {
  description = "API Gateway endpoint URL for Telegram webhook"
  value       = "${aws_apigatewayv2_stage.prod_with_logging.invoke_url}/webhook"
}

output "api_gateway_url" {
  description = "Base API Gateway URL"
  value       = aws_apigatewayv2_stage.prod_with_logging.invoke_url
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.telegram_lambda.function_name
}

output "lambda_function_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.telegram_lambda.arn
}

output "s3_bucket_name" {
  description = "S3 bucket name for file storage"
  value       = aws_s3_bucket.telegram_files.id
}

output "dynamodb_table_name" {
  description = "DynamoDB table name"
  value       = aws_dynamodb_table.telegram_messages.name
}

output "cloudwatch_log_group_lambda" {
  description = "CloudWatch Log Group for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "cloudwatch_log_group_api_gateway" {
  description = "CloudWatch Log Group for API Gateway"
  value       = aws_cloudwatch_log_group.api_gateway_logs.name
}

output "webhook_setup_command" {
  description = "Command to set Telegram webhook (replace YOUR_BOT_TOKEN)"
  value       = "curl -X POST https://api.telegram.org/botYOUR_BOT_TOKEN/setWebhook -H 'Content-Type: application/json' -d '{\"url\": \"${aws_apigatewayv2_stage.prod_with_logging.invoke_url}/webhook\"}'"
}

output "sns_topic_arn" {
  description = "SNS Topic ARN for alerts (if configured)"
  value       = var.alarm_email != "" ? aws_sns_topic.alerts[0].arn : "Not configured"
}

output "region" {
  description = "AWS Region"
  value       = var.aws_region
}
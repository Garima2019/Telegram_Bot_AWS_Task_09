############################################
# TERRAFORM & PROVIDERS
############################################

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

############################################
# S3 BUCKET FOR FILE STORAGE
############################################

resource "aws_s3_bucket" "telegram_files" {
  bucket = var.s3_bucket_name

  # In dev you can allow force_destroy, in other envs keep it safe
  force_destroy = var.environment == "dev" ? true : false

  tags = {
    Name        = "Telegram Bot Files"
    Environment = var.environment
  }
}

# Block public access to the bucket
resource "aws_s3_bucket_public_access_block" "telegram_files" {
  bucket = aws_s3_bucket.telegram_files.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption by default
resource "aws_s3_bucket_server_side_encryption_configuration" "telegram_files" {
  bucket = aws_s3_bucket.telegram_files.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning (optional but recommended)
resource "aws_s3_bucket_versioning" "telegram_files" {
  bucket = aws_s3_bucket.telegram_files.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle (optional – clean up old versions after 365 days)
resource "aws_s3_bucket_lifecycle_configuration" "telegram_files" {
  bucket = aws_s3_bucket.telegram_files.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

############################################
# DYNAMODB TABLE
############################################

resource "aws_dynamodb_table" "telegram_messages" {
  name         = var.ddb_table_name
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "user_id"
  range_key = "sort_key"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "sort_key"
    type = "S"
  }

  tags = {
    Name        = "Telegram Bot Messages"
    Environment = var.environment
  }
}

############################################
# IAM ROLE FOR LAMBDA
############################################

resource "aws_iam_role" "lambda_role" {
  name = "telegram-bot-lambda-role-v2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action   = "sts:AssumeRole"
    }]
  })
}

# Basic Lambda execution permissions (logs)
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# DynamoDB access
resource "aws_iam_role_policy" "lambda_dynamodb_access" {
  name = "telegram-lambda-ddb-access-v2"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = aws_dynamodb_table.telegram_messages.arn
      }
    ]
  })
}

# S3 access
resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "telegram-lambda-s3-access-v2"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.telegram_files.arn,
          "${aws_s3_bucket.telegram_files.arn}/*"
        ]
      }
    ]
  })
}

############################################
# LAMBDA PACKAGING
############################################

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/handler.py"
  output_path = "${path.module}/lambda.zip"
}

############################################
# LAMBDA FUNCTION
############################################

resource "aws_lambda_function" "telegram_lambda" {
  function_name = "telegram-bot-lambda-v2"
  role          = aws_iam_role.lambda_role.arn

  handler = "handler.lambda_handler"
  runtime = "python3.11"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  memory_size = 512
  timeout     = 60

  environment {
    variables = {
      TELEGRAM_BOT_TOKEN = var.telegram_bot_token
      DDB_TABLE_NAME     = aws_dynamodb_table.telegram_messages.name
      S3_BUCKET_NAME     = aws_s3_bucket.telegram_files.id
      OPENAI_API_KEY     = var.openai_api_key
      GEMINI_API_KEY     = var.gemini_api_key
      # AWS_ENDPOINT_URL removed – this is REAL AWS, not LocalStack
    }
  }

  depends_on = [
    aws_iam_role.lambda_role,
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.lambda_dynamodb_access,
    aws_iam_role_policy.lambda_s3_access
  ]
}

############################################
# API GATEWAY HTTP API
############################################

resource "aws_apigatewayv2_api" "telegram_api" {
  name          = "telegram-http-api-v2"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id                 = aws_apigatewayv2_api.telegram_api.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  integration_uri        = aws_lambda_function.telegram_lambda.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "telegram_route" {
  api_id    = aws_apigatewayv2_api.telegram_api.id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

############################################
# API GATEWAY STAGE & LOGGING
############################################

resource "aws_cloudwatch_log_group" "apigw_logs" {
  name              = "/aws/apigateway/telegram-http-api-v2"
  retention_in_days = 7
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.telegram_api.id
  name        = "prod"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_logs.arn
    format = jsonencode({
      requestId   = "$context.requestId"
      ip          = "$context.identity.sourceIp"
      httpMethod  = "$context.httpMethod"
      routeKey    = "$context.routeKey"
      status      = "$context.status"
      protocol    = "$context.protocol"
      responseLen = "$context.responseLength"
      error       = "$context.integrationErrorMessage"
    })
  }

  depends_on = [aws_cloudwatch_log_group.apigw_logs]
}

############################################
# LAMBDA PERMISSION FOR API GATEWAY
############################################

resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.telegram_lambda.arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.telegram_api.execution_arn}/*/*"
}

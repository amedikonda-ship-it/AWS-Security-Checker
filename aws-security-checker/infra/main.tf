# -----------------------------------------------------------------------------
# 1. S3 BUCKET FOR AUDIT REPORTS
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "audit_reports" {
  bucket        = "aws-iam-security-audit-reports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# 2. IAM ROLE & POLICIES FOR LAMBDA
# -----------------------------------------------------------------------------
resource "aws_iam_role" "lambda_exec" {
  name = "aws_security_scanner_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_permissions" {
  name = "aws_security_scanner_lambda_permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "S3ReportBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.audit_reports.arn}/*"
      },
      {
        Sid      = "STSAssumeCustomerRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_permissions.arn
}

# -----------------------------------------------------------------------------
# 3. PACKAGING PYTHON CODE (ZIPPING ON THE FLY)
# -----------------------------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src" # Points to your Python code folder
  output_path = "${path.module}/lambda_function.zip"
}

# -----------------------------------------------------------------------------
# 4. LAMBDA FUNCTION DEPLOYMENT
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "scanner" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "aws-iam-security-scanner"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler" # Assumes handler.py with lambda_handler(event, context)
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.10"
  timeout          = 60 # Set to 60s to allow polling credential reports

    environment {
        variables = {
        REPORT_BUCKET_NAME = aws_s3_bucket.audit_reports.bucket
        }
    }
}

# -----------------------------------------------------------------------------
# 5. API GATEWAY (HTTP API) + CORS + THROTTLING (10 RPS)
# -----------------------------------------------------------------------------
resource "aws_apigatewayv2_api" "http_api" {
  name          = "aws-security-scanner-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["POST", "OPTIONS", "GET"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id                 = aws_apigatewayv2_api.http_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.scanner.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "scan_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /scan"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

resource "aws_apigatewayv2_stage" "default_stage" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true

  # Throttling controls (Financial Circuit Breaker: 10 requests per second)
  default_route_settings {
    throttling_rate_limit  = 10
    throttling_burst_limit = 5
  }
}

# -----------------------------------------------------------------------------
# 6. API GATEWAY INVOCATION PERMISSION TO LAMBDA
# -----------------------------------------------------------------------------
resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------
output "api_endpoint" {
  description = "The public URL to trigger your security scanning engine"
  value       = aws_apigatewayv2_api.http_api.api_endpoint
}

output "s3_bucket_name" {
  description = "S3 bucket storing final reports"
  value       = aws_s3_bucket.audit_reports.bucket
}
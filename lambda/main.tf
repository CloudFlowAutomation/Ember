# CommSecure lobby — Lambda deployment.
#
# Provisions everything lobby_lambda.py needs: the function (with a public
# Function URL the Electron app uses as LOBBY_URL), the DynamoDB join-code
# table, an IAM role allowing the MicroVM control-plane calls, and the
# CommSecureRoomRole execution role room VMs use to self-terminate.
#
#   terraform init
#   terraform apply -var microvm_image_arn=arn:aws:lambda:…:microvm-image:commsecure-room
#
# The room image itself is still built by scripts/deploy_room_image.sh;
# pass its ARN in via microvm_image_arn.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source = "hashicorp/archive"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "microvm_image_arn" {
  description = "MicroVM image the lobby launches per room (from scripts/deploy_room_image.sh)"
  type        = string
}

variable "rooms_table_name" {
  type    = string
  default = "commsecure-rooms"
}

variable "room_idle_seconds" {
  type    = number
  default = 600
}

provider "aws" {
  region = var.region
}

# The runtime's bundled boto3 predates the lambda-microvms service, so the
# zip must carry its own; a handler-only zip fails with UnknownServiceError.
resource "terraform_data" "lobby_bundle" {
  triggers_replace = [filesha256("${path.module}/lobby_lambda.py")]

  provisioner "local-exec" {
    command = <<-EOT
      set -e
      rm -rf '${path.module}/.terraform/build'
      uv pip install --quiet --target '${path.module}/.terraform/build' boto3
      cp '${path.module}/lobby_lambda.py' '${path.module}/.terraform/build/'
    EOT
  }
}

data "archive_file" "lobby" {
  type        = "zip"
  source_dir  = "${path.module}/.terraform/build"
  output_path = "${path.module}/.terraform/lobby_lambda.zip"
  depends_on  = [terraform_data.lobby_bundle]
}

resource "aws_dynamodb_table" "rooms" {
  name         = var.rooms_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "code"

  attribute {
    name = "code"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# Execution role for the room MicroVMs themselves: lets a room's relay
# call terminate-microvm on its own VM when idle (see room_watchdog).
resource "aws_iam_role" "room" {
  name = "CommSecureRoomRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

resource "aws_iam_role_policy" "room" {
  name = "self-terminate"
  role = aws_iam_role.room.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:TerminateMicrovm"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "lobby" {
  name = "commsecure-lobby-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lobby.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lobby" {
  name = "lobby"
  role = aws_iam_role.lobby.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = aws_dynamodb_table.rooms.arn
      },
      {
        # MicroVM actions live in the lambda: namespace (see README).
        Effect = "Allow"
        Action = [
          "lambda:RunMicrovm",
          "lambda:GetMicrovm",
          "lambda:CreateMicrovmAuthToken",
        ]
        Resource = "*"
      },
      {
        # run_microvm passes the room VMs' execution role.
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.room.arn
      },
      {
        # run_microvm also passes the AWS-managed internet-egress
        # network connector so rooms get outbound connectivity.
        Effect   = "Allow"
        Action   = "lambda:PassNetworkConnector"
        Resource = "*"
      },
    ]
  })
}

resource "aws_lambda_function" "lobby" {
  function_name    = "commsecure-lobby"
  role             = aws_iam_role.lobby.arn
  runtime          = "python3.13"
  handler          = "lobby_lambda.lambda_handler"
  filename         = data.archive_file.lobby.output_path
  source_code_hash = data.archive_file.lobby.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ROOMS_TABLE                = aws_dynamodb_table.rooms.name
      MICROVM_IMAGE_ARN          = var.microvm_image_arn
      MICROVM_EXECUTION_ROLE_ARN = aws_iam_role.room.arn
      ROOM_IDLE_SECONDS          = tostring(var.room_idle_seconds)
    }
  }
}

# Public URL; auth is by unguessable join code + short room lifetimes,
# same trust model as the FastAPI lobby. CORS (incl. OPTIONS preflight
# from the app's file:// origin) is answered by the handler itself.
resource "aws_lambda_function_url" "lobby" {
  function_name      = aws_lambda_function.lobby.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "public_url" {
  statement_id           = "AllowPublicFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.lobby.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

output "lobby_url" {
  description = "Point the Electron app's LOBBY_URL here"
  value       = aws_lambda_function_url.lobby.function_url
}

output "rooms_table" {
  value = aws_dynamodb_table.rooms.name
}

output "room_role_arn" {
  description = "Also usable as MICROVM_EXECUTION_ROLE_ARN for the uvicorn lobby"
  value       = aws_iam_role.room.arn
}

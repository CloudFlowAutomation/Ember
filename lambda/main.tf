# ember lobby — Lambda deployment.
#
# Provisions everything lobby_lambda.py needs: the function (with a public
# Function URL the Electron app uses as LOBBY_URL), the DynamoDB join-code
# table, an IAM role allowing the MicroVM control-plane calls, and the
# emberRoomRole execution role room VMs use to self-terminate.
#
#   terraform init
#   terraform apply -var microvm_image_arn=arn:aws:lambda:…:microvm-image:ember-room
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
    random = {
      source = "hashicorp/random"
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
  default = "ember-rooms"
}

variable "room_idle_seconds" {
  type    = number
  default = 600
}

provider "aws" {
  region = var.region
}

# Shared API key the Electron app must send as X-Api-Key on every lobby
# request. Stored in SSM so it never lands in the function's plain-text
# environment; the lambda reads it once per sandbox. Read it out with:
#   terraform output -raw lobby_api_key
# Rotate by tainting: terraform apply -replace=random_password.lobby_api_key
resource "random_password" "lobby_api_key" {
  length  = 40
  special = false
}

resource "aws_ssm_parameter" "lobby_api_key" {
  name  = "/ember/lobby-api-key"
  type  = "SecureString"
  value = random_password.lobby_api_key.result
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
  name = "emberRoomRole"
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
  name = "ember-lobby-lambda"
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
        # Decryption uses the AWS-managed aws/ssm key, which needs no
        # explicit kms:Decrypt grant.
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = aws_ssm_parameter.lobby_api_key.arn
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
      {
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = aws_ssm_parameter.lobby_api_key.arn
      },
    ]
  })
}

resource "aws_lambda_function" "lobby" {
  function_name    = "ember-lobby"
  role             = aws_iam_role.lobby.arn
  runtime          = "python3.13"
  handler          = "lobby_lambda.lambda_handler"
  filename         = data.archive_file.lobby.output_path
  source_code_hash = data.archive_file.lobby.output_base64sha256
  # /rooms/{code}/extend calls into the room VM, which may need to
  # auto-resume from suspension first.
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      ROOMS_TABLE                = aws_dynamodb_table.rooms.name
      MICROVM_IMAGE_ARN          = var.microvm_image_arn
      MICROVM_EXECUTION_ROLE_ARN = aws_iam_role.room.arn
      ROOM_IDLE_SECONDS          = tostring(var.room_idle_seconds)
      LOBBY_API_KEY_PARAM        = aws_ssm_parameter.lobby_api_key.name
    }
  }
}

# Public URL; the handler itself checks X-Api-Key against the SSM
# parameter, and rooms are further guarded by unguessable join codes +
# short lifetimes. CORS (incl. OPTIONS preflight from the app's file://
# origin) is answered by the handler too.
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

output "lobby_api_key" {
  description = "Paste into the app's Settings → Rooms API key (terraform output -raw lobby_api_key)"
  value       = random_password.lobby_api_key.result
  sensitive   = true
}

output "rooms_table" {
  value = aws_dynamodb_table.rooms.name
}

output "room_role_arn" {
  description = "Also usable as MICROVM_EXECUTION_ROLE_ARN for the uvicorn lobby"
  value       = aws_iam_role.room.arn
}

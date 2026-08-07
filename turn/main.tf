# CommSecure call server — coturn (STUN/TURN) on ECS Fargate behind an NLB.
#
# Separate, self-contained stack from lambda/ — this is a plain always-on
# service, not a per-room MicroVM. Point commsecure's Settings -> Call
# server fields at this stack's outputs (turn_url / turn_username /
# turn_credential) once applied.
#
#   terraform init
#   terraform apply -var vpc_id=vpc-xxxx -var subnet_id=subnet-xxxx
#
# Trade-off worth knowing: the control port (3478, what clients first talk
# to for STUN binding and TURN allocate/permission requests) sits behind
# the NLB's Elastic IP, which is stable across redeploys — that's what
# turn_url points at. Actual TURN-relayed media (only used as a fallback
# when two peers can't reach each other even with STUN, e.g. symmetric
# NAT) flows directly to the Fargate task's own public IP on the relay
# port range, bypassing the NLB — because relaying that range through the
# NLB too would mean one NLB listener + target group per relay port, which
# isn't worth the complexity for a small deployment. That IP can change on
# redeploy, but it only affects the TURN-fallback path, not STUN itself or
# turn_url's stability.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
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

variable "vpc_id" {
  description = "VPC to run the coturn task and NLB in."
  type        = string
}

variable "subnet_id" {
  description = "Public subnet (single-AZ — see header comment on why this stack doesn't span multiple AZs) with a route to an internet gateway."
  type        = string
}

variable "turn_realm" {
  description = "Realm coturn presents to clients; cosmetic, doesn't need to resolve to anything."
  type        = string
  default     = "commsecure.turn"
}

variable "image" {
  description = "coturn container image. Pinned, not :latest, so a redeploy doesn't silently change behavior."
  type        = string
  default     = "coturn/coturn:4.6.2-alpine"
}

variable "cpu" {
  type    = number
  default = 256
}

variable "memory" {
  type    = number
  default = 512
}

variable "desired_count" {
  description = "Keep at 1 unless you also solve multi-instance relay-port routing (see header comment)."
  type        = number
  default     = 1
}

variable "min_relay_port" {
  type    = number
  default = 49152
}

variable "max_relay_port" {
  description = "Bounds concurrent TURN-relayed call legs to (max - min + 1). 20 ports is plenty for a small deployment; each active relayed call holds one."
  type        = number
  default     = 49171
}

provider "aws" {
  region = var.region
}

resource "random_password" "turn_credential" {
  length  = 32
  special = false
}

locals {
  turn_username = "commsecure"
}

resource "aws_ssm_parameter" "turn_credential" {
  name  = "/commsecure/turn-credential"
  type  = "SecureString"
  value = random_password.turn_credential.result
}

resource "aws_eip" "turn" {
  domain = "vpc"
}

resource "aws_security_group" "turn" {
  name   = "commsecure-turn"
  vpc_id = var.vpc_id

  ingress {
    description = "STUN/TURN control"
    from_port   = 3478
    to_port     = 3478
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "TURN control over TCP (fallback when UDP is blocked)"
    from_port   = 3478
    to_port     = 3478
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "TURN relayed media — reaches the task's own public IP directly, not through the NLB"
    from_port   = var.min_relay_port
    to_port     = var.max_relay_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_cluster" "turn" {
  name = "commsecure-turn"
}

resource "aws_cloudwatch_log_group" "turn" {
  name              = "/ecs/commsecure-turn"
  retention_in_days = 14
}

resource "aws_iam_role" "execution" {
  name = "commsecure-turn-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The execution role (not the task role) is what fetches `secrets` values
# on the container's behalf before it starts.
resource "aws_iam_role_policy" "execution_ssm" {
  name = "read-turn-credential"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "ssm:GetParameters"
      Resource = aws_ssm_parameter.turn_credential.arn
    }]
  })
}

resource "aws_ecs_task_definition" "turn" {
  family                   = "commsecure-turn"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn

  container_definitions = jsonencode([
    {
      name      = "coturn"
      image     = var.image
      essential = true
      # awsvpc gives the container the task's own ENI directly, so
      # portMappings here are documentation, not what makes ports
      # reachable — the security group governs that.
      portMappings = [
        { containerPort = 3478, protocol = "udp" },
        { containerPort = 3478, protocol = "tcp" },
      ]
      secrets = [
        { name = "TURN_PASSWORD", valueFrom = aws_ssm_parameter.turn_credential.arn },
      ]
      entryPoint = ["sh", "-c"]
      command = [
        <<-EOT
        turnserver -n --log-file=stdout \
          --realm=${var.turn_realm} \
          --lt-cred-mech --user=${local.turn_username}:$TURN_PASSWORD \
          --external-ip=$(wget -qO- --timeout=3 https://checkip.amazonaws.com) \
          --min-port=${var.min_relay_port} --max-port=${var.max_relay_port} \
          --no-cli --fingerprint
        EOT
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.turn.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "coturn"
        }
      }
    }
  ])
}

resource "aws_lb" "turn" {
  name               = "commsecure-turn"
  load_balancer_type = "network"
  internal           = false

  subnet_mapping {
    subnet_id     = var.subnet_id
    allocation_id = aws_eip.turn.id
  }
}

# UDP/TCP target groups require a TCP health check — UDP itself has no
# handshake for the NLB to probe. coturn answers TCP connects on 3478 too
# (it listens for TURN-over-TCP), so this reuses the same port.
resource "aws_lb_target_group" "turn_udp" {
  name        = "commsecure-turn-udp"
  port        = 3478
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    protocol = "TCP"
    port     = "3478"
  }
}

resource "aws_lb_target_group" "turn_tcp" {
  name        = "commsecure-turn-tcp"
  port        = 3478
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    protocol = "TCP"
    port     = "3478"
  }
}

resource "aws_lb_listener" "turn_udp" {
  load_balancer_arn = aws_lb.turn.arn
  port              = 3478
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.turn_udp.arn
  }
}

resource "aws_lb_listener" "turn_tcp" {
  load_balancer_arn = aws_lb.turn.arn
  port              = 3478
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.turn_tcp.arn
  }
}

resource "aws_ecs_service" "turn" {
  name            = "commsecure-turn"
  cluster         = aws_ecs_cluster.turn.id
  task_definition = aws_ecs_task_definition.turn.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [var.subnet_id]
    security_groups  = [aws_security_group.turn.id]
    # Direct public IP so TURN-relayed media (see header comment) has
    # somewhere to go that isn't the NLB.
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.turn_udp.arn
    container_name   = "coturn"
    container_port   = 3478
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.turn_tcp.arn
    container_name   = "coturn"
    container_port   = 3478
  }
}

output "turn_url" {
  description = "Paste into commsecure Settings -> Call server (STUN/TURN)"
  value       = "turn:${aws_eip.turn.public_ip}:3478"
}

output "turn_username" {
  value = local.turn_username
}

output "turn_credential" {
  description = "Paste into commsecure Settings -> Call server credential (terraform output -raw turn_credential)"
  value       = random_password.turn_credential.result
  sensitive   = true
}

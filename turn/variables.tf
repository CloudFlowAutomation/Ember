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
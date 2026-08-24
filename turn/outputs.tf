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
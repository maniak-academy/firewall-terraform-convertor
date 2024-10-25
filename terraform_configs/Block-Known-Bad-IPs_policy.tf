resource "fortios_firewall_policy" "Block_Known_Bad_IPs" {
  name        = "Block-Known-Bad-IPs"
  srcintf     = ["Extranet", "Users_Net"]
  dstintf     = ["Internet"]
  srcaddr     = ["any"]
  dstaddr     = ["IR", "Malicious-IP-Group", "panw-bulletproof-ip-list", "panw-highrisk-ip-list", "panw-known-ip-list"]
  action      = "deny"
  schedule    = "always"
  service     = ["application-default"]
  comments    = "Blocks traffic to malicious addresses and regions."
}
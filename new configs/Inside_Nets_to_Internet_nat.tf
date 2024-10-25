
# Source NAT Rule: Inside_Nets_to_Internet
resource "fortios_firewall_policy" "Inside_Nets_to_Internet_snat_policy" {
  name        = "Inside_Nets_to_Internet"
  srcintf     = ["Extranet", "Users_Net"]
  dstintf     = ["Internet"]
  srcaddr     = ["any"]
  dstaddr     = ["any"]
  action      = "accept"
  schedule    = "always"
  service     = ["any"]
  nat         = "enable"
  comments    = "Translates traffic from User_Net and Extranet zones to 203.0.113.20 outbound to Internet"

  ippool = "enable"
  poolname = ["203.0.113.20/24"]
}

# IP Pool for SNAT
resource "fortios_firewall_ippool" "Inside_Nets_to_Internet_ippool" {
  name    = "203.0.113.20/24"
  startip = "203.0.113.20/24"
  endip   = "203.0.113.20/24"
  type    = "overload"
}

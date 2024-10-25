resource "fortios_firewall_policy" "Users_to_Extranet" {
  name        = "Users_to_Extranet"
  srcintf     = ["Users_Net"]
  dstintf     = ["Extranet"]
  srcaddr     = ["any"]
  dstaddr     = ["any"]
  action      = "accept"
  schedule    = "always"
  service     = ["application-default"]
  comments    = "Allows hosts in Users_Net zone to access servers in Extranet zone."
}
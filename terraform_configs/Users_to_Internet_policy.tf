resource "fortios_firewall_policy" "Users_to_Internet" {
  name        = "Users_to_Internet"
  srcintf     = ["Users_Net"]
  dstintf     = ["Internet"]
  srcaddr     = ["any"]
  dstaddr     = ["any"]
  action      = "accept"
  schedule    = "always"
  service     = ["application-default"]
  comments    = "Allows hosts in Users_Net zone to access Internet zone."
}
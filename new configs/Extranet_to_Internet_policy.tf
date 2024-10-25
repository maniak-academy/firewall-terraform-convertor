resource "fortios_firewall_policy" "Extranet_to_Internet" {
  name        = "Extranet_to_Internet"
  srcintf     = ["Extranet"]
  dstintf     = ["Internet"]
  srcaddr     = ["any"]
  dstaddr     = ["any"]
  action      = "accept"
  schedule    = "always"
  service     = ["application-default"]
  comments    = "Allows hosts in Extranet zone to access Internet zone."
}
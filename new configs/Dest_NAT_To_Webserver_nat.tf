
# Destination NAT Rule: Dest_NAT_To_Webserver
resource "fortios_firewall_vip" "Dest_NAT_To_Webserver" {
  name        = "Dest_NAT_To_Webserver"
  extintf     = "Users_Net"
  extip       = "192.168.1.80"
  mappedip    = "192.168.50.80"
  portforward = false
  comment     = "Translates traffic to web server at 192.168.50.80."
}

# Policy to allow traffic to the VIP
resource "fortios_firewall_policy" "Dest_NAT_To_Webserver_policy" {
  name        = "Dest_NAT_To_Webserver_Policy"
  srcintf     = ["Users_Net"]
  dstintf     = ["Users_Net"]
  srcaddr     = ["any"]
  dstaddr     = ["Dest_NAT_To_Webserver"]
  action      = "accept"
  schedule    = "always"
  service     = ["any"]
  comments    = "Translates traffic to web server at 192.168.50.80."
}

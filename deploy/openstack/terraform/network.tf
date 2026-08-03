# Private network + router. Every instance sits on the private network and
# reaches the outside through the router's SNAT; inbound arrives on a floating IP
# that is 1:1 NAT'd onto the private address.
#
# That NAT is the reason two settings later are not optional:
#   - a relay advertises `public_ip` STATICALLY to TURN clients, so it must be
#     told its floating IP (the instance only ever sees the private one), and
#   - a controller advertises its own DNS name into the signed cluster map, and
#     controllers resolve each other to PRIVATE addresses via /etc/hosts, because
#     hairpinning out to a sibling's floating IP and back in is unreliable in
#     OpenStack. Both are handled by the Ansible.

resource "openstack_networking_network_v2" "private" {
  name           = "${var.name_prefix}-net"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "private" {
  name            = "${var.name_prefix}-subnet"
  network_id      = openstack_networking_network_v2.private.id
  cidr            = var.private_cidr
  ip_version      = 4
  dns_nameservers = var.dns_nameservers
}

resource "openstack_networking_router_v2" "router" {
  name                = "${var.name_prefix}-router"
  admin_state_up      = true
  external_network_id = var.public_network_id
}

resource "openstack_networking_router_interface_v2" "router_private" {
  router_id = openstack_networking_router_v2.router.id
  subnet_id = openstack_networking_subnet_v2.private.id
}

# ---------------------------------------------------------------------------
# Keypair
# ---------------------------------------------------------------------------

resource "openstack_compute_keypair_v2" "this" {
  count      = var.ssh_keypair_name == "" ? 1 : 0
  name       = "${var.name_prefix}-key"
  public_key = var.ssh_public_key
}

locals {
  keypair_name = var.ssh_keypair_name != "" ? var.ssh_keypair_name : openstack_compute_keypair_v2.this[0].name
}

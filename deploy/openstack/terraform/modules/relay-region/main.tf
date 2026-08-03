# A relay cell in one region — or one entirely separate cloud/Keystone. It owns
# its own network, router, security group and floating IPs, because every one of
# those IDs is scoped to the cloud it lives in and cannot be shared across them.
#
# Relays are deliberately self-contained: they hold no session state, see only
# ciphertext, and self-register to the controllers over the public control
# channel. That is what makes it safe to put them on cheap or foreign
# infrastructure — a compromised relay learns traffic timing and volume, nothing
# more.

terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 2.1"
    }
  }
}

data "openstack_images_image_v2" "base" {
  name        = var.image_name
  most_recent = true
}

data "openstack_networking_network_v2" "public" {
  network_id = var.public_network_id
}

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

# Relays are spread across hosts too: losing one hypervisor should degrade the
# relay floor, not remove it.
resource "openstack_compute_servergroup_v2" "relays" {
  name     = "${var.name_prefix}-relays"
  policies = [var.anti_affinity_policy]
}

# ---------------------------------------------------------------------------
# Security group — per cloud, since a group ID cannot cross Keystones.
#
# 7403/tcp and 7404/udp face the world by necessity: any client or agent, from
# any network, must be able to reach the rendezvous and the TURN floor. That is
# the relay's whole job. It accepts nothing else, and notably nothing FROM the
# controllers — registration is relay-initiated.
# ---------------------------------------------------------------------------

resource "openstack_networking_secgroup_v2" "relay" {
  name                 = "${var.name_prefix}-relay"
  description          = "Geneza relay: rendezvous + TURN floor"
  delete_default_rules = true
}

resource "openstack_networking_secgroup_rule_v2" "egress_v4" {
  direction         = "egress"
  ethertype         = "IPv4"
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

resource "openstack_networking_secgroup_rule_v2" "ssh" {
  for_each          = toset(var.admin_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

resource "openstack_networking_secgroup_rule_v2" "rendezvous" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 7403
  port_range_max    = 7403
  remote_ip_prefix  = "0.0.0.0/0"
  description       = "TLS rendezvous floor"
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

# UDP is the one people forget, and its absence looks like "p2p mysteriously
# never works" rather than a clean failure.
resource "openstack_networking_secgroup_rule_v2" "turn" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 7404
  port_range_max    = 7404
  remote_ip_prefix  = "0.0.0.0/0"
  description       = "STUN/TURN data plane"
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

# ---------------------------------------------------------------------------
# Instances
# ---------------------------------------------------------------------------

resource "openstack_networking_port_v2" "relay" {
  count              = var.count_
  name               = "${var.name_prefix}-relay${count.index + 1}-port"
  network_id         = openstack_networking_network_v2.private.id
  admin_state_up     = true
  security_group_ids = [openstack_networking_secgroup_v2.relay.id]

  fixed_ip {
    subnet_id = openstack_networking_subnet_v2.private.id
  }
}

resource "openstack_compute_instance_v2" "relay" {
  # Read cloud-init data from a config drive rather than only the metadata
  # service. Without it a booting instance that cannot reach 169.254.169.254 in
  # time falls back to DataSourceNone, silently skips SSH key injection, and
  # comes up ACTIVE but unreachable — observed on this exact stack.
  config_drive = true
  count        = var.count_
  name         = "${var.name_prefix}-relay${count.index + 1}"
  flavor_name  = var.flavor
  key_pair     = var.keypair_name

  scheduler_hints {
    group = openstack_compute_servergroup_v2.relays.id
  }

  block_device {
    uuid                  = data.openstack_images_image_v2.base.id
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = var.volume_size
    volume_type           = var.volume_type
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    port = openstack_networking_port_v2.relay[count.index].id
  }

  lifecycle {
    ignore_changes = [block_device]
  }
}

resource "openstack_networking_floatingip_v2" "relay" {
  count       = var.count_
  pool        = data.openstack_networking_network_v2.public.name
  description = "${var.name_prefix}-relay${count.index + 1}"
}

resource "openstack_networking_floatingip_associate_v2" "relay" {
  count       = var.count_
  floating_ip = openstack_networking_floatingip_v2.relay[count.index].address
  port_id     = openstack_networking_port_v2.relay[count.index].id

  # Neutron refuses the association until this subnet has a route to the
  # external network. No argument here references the router interface, so the
  # dependency has to be explicit or Terraform races and the apply fails.
  depends_on = [openstack_networking_router_interface_v2.router_private]
}

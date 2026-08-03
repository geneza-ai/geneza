# Home-region relays live in the control plane's own network, so they are
# declared here rather than through the module (they share the router, subnet and
# keypair already created). Cross-region relays go through the module, one call
# per provider alias.

resource "openstack_networking_secgroup_v2" "relay" {
  name                 = "${var.name_prefix}-relay"
  description          = "Geneza relay: rendezvous + TURN floor"
  delete_default_rules = true
}

resource "openstack_networking_secgroup_rule_v2" "relay_egress_v4" {
  direction         = "egress"
  ethertype         = "IPv4"
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

resource "openstack_networking_secgroup_rule_v2" "relay_ssh" {
  for_each          = toset(var.admin_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

resource "openstack_networking_secgroup_rule_v2" "relay_rendezvous" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 7403
  port_range_max    = 7403
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

resource "openstack_networking_secgroup_rule_v2" "relay_turn" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 7404
  port_range_max    = 7404
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.relay.id
}

resource "openstack_compute_servergroup_v2" "relays" {
  name     = "${var.name_prefix}-relays"
  policies = ["soft-anti-affinity"]
}

resource "openstack_networking_port_v2" "relay" {
  count              = var.home_relay_count
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
  count        = var.home_relay_count
  name         = "${var.name_prefix}-relay${count.index + 1}"
  flavor_name  = var.relay_flavor
  key_pair     = local.keypair_name

  scheduler_hints {
    group = openstack_compute_servergroup_v2.relays.id
  }

  block_device {
    uuid                  = data.openstack_images_image_v2.base.id
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = var.relay_volume_size
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
  count       = var.home_relay_count
  pool        = data.openstack_networking_network_v2.public.name
  subnet_id   = var.public_subnet_id != "" ? var.public_subnet_id : null
  description = "${var.name_prefix}-relay${count.index + 1}"
}

resource "openstack_networking_floatingip_associate_v2" "relay" {
  count       = var.home_relay_count
  floating_ip = openstack_networking_floatingip_v2.relay[count.index].address
  port_id     = openstack_networking_port_v2.relay[count.index].id

  # See the controller association: the subnet needs its router path before
  # Neutron will accept a floating IP on a port in it.
  depends_on = [openstack_networking_router_interface_v2.router_private]
}

# ---------------------------------------------------------------------------
# Cross-region / cross-cloud relays
#
# Terraform cannot pick a provider alias from a for_each key — provider wiring is
# resolved before values are known — so there is one module block per alias
# rather than one loop. Each is gated on its key being present in
# var.relay_regions, so an unused region creates nothing. To add a fourth
# location: declare a provider alias in versions.tf and copy one block.
# ---------------------------------------------------------------------------

module "relay_b" {
  source   = "./modules/relay-region"
  for_each = contains(keys(var.relay_regions), "relay_b") ? { relay_b = var.relay_regions["relay_b"] } : {}

  providers = { openstack = openstack.relay_b }

  name_prefix       = "${var.name_prefix}-${each.key}"
  image_name        = var.image_name
  flavor            = each.value.flavor
  keypair_name      = local.keypair_name
  public_network_id = each.value.public_network_id
  volume_type       = each.value.volume_type
  volume_size       = each.value.volume_size
  private_cidr      = each.value.private_cidr
  count_            = each.value.count
  admin_cidrs       = var.admin_cidrs
  region_id         = each.value.region_id != "" ? each.value.region_id : each.key
}

module "relay_c" {
  source   = "./modules/relay-region"
  for_each = contains(keys(var.relay_regions), "relay_c") ? { relay_c = var.relay_regions["relay_c"] } : {}

  providers = { openstack = openstack.relay_c }

  name_prefix       = "${var.name_prefix}-${each.key}"
  image_name        = var.image_name
  flavor            = each.value.flavor
  keypair_name      = local.keypair_name
  public_network_id = each.value.public_network_id
  volume_type       = each.value.volume_type
  volume_size       = each.value.volume_size
  private_cidr      = each.value.private_cidr
  count_            = each.value.count
  admin_cidrs       = var.admin_cidrs
  region_id         = each.value.region_id != "" ? each.value.region_id : each.key
}

# A relay in a DIFFERENT cloud entirely (its own Keystone). The keypair is
# per-cloud, so this one registers its own from var.ssh_public_key.
module "relay_foreign" {
  source   = "./modules/relay-region"
  for_each = contains(keys(var.relay_regions), "relay_foreign") ? { relay_foreign = var.relay_regions["relay_foreign"] } : {}

  providers = { openstack = openstack.relay_foreign }

  name_prefix       = "${var.name_prefix}-${each.key}"
  image_name        = var.image_name
  flavor            = each.value.flavor
  keypair_name      = var.ssh_keypair_name
  public_network_id = each.value.public_network_id
  volume_type       = each.value.volume_type
  volume_size       = each.value.volume_size
  private_cidr      = each.value.private_cidr
  count_            = each.value.count
  admin_cidrs       = var.admin_cidrs
  region_id         = each.value.region_id != "" ? each.value.region_id : each.key
}

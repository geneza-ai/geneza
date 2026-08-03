data "openstack_images_image_v2" "base" {
  name        = var.image_name
  most_recent = true
}

# Controllers must not share a hypervisor: losing one host would otherwise take
# the whole "HA" control plane with it. Hard anti-affinity FAILS the build when
# the region cannot place them apart, which is the correct outcome — a silently
# co-located pair is worse than a failed apply.
resource "openstack_compute_servergroup_v2" "controllers" {
  name     = "${var.name_prefix}-controllers"
  policies = [var.anti_affinity_policy]
}

resource "openstack_networking_port_v2" "controller" {
  count              = var.controller_count
  name               = "${var.name_prefix}-gw${count.index + 1}-port"
  network_id         = openstack_networking_network_v2.private.id
  admin_state_up     = true
  security_group_ids = [openstack_networking_secgroup_v2.controller.id]

  fixed_ip {
    subnet_id = openstack_networking_subnet_v2.private.id
  }
}

resource "openstack_compute_instance_v2" "controller" {
  # Read cloud-init data from a config drive rather than only the metadata
  # service. Without it a booting instance that cannot reach 169.254.169.254 in
  # time falls back to DataSourceNone, silently skips SSH key injection, and
  # comes up ACTIVE but unreachable — observed on this exact stack.
  config_drive = true
  count        = var.controller_count
  name         = "${var.name_prefix}-gw${count.index + 1}"
  flavor_name  = var.controller_flavor
  key_pair     = local.keypair_name

  scheduler_hints {
    group = openstack_compute_servergroup_v2.controllers.id
  }

  # Boot from volume, always: the root disk survives a rebuild and is sized
  # independently of the flavor.
  block_device {
    uuid                  = data.openstack_images_image_v2.base.id
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = var.controller_volume_size
    volume_type           = var.volume_type
    boot_index            = 0
    delete_on_termination = true
  }

  network {
    port = openstack_networking_port_v2.controller[count.index].id
  }

  lifecycle {
    # The image is a build-time input; a new upstream image should not silently
    # recreate the control plane. Roll instances deliberately instead.
    ignore_changes = [block_device]
  }
}

resource "openstack_networking_floatingip_v2" "controller" {
  count       = var.controller_count
  pool        = data.openstack_networking_network_v2.public.name
  subnet_id   = var.public_subnet_id != "" ? var.public_subnet_id : null
  description = "${var.name_prefix}-gw${count.index + 1}"
}

resource "openstack_networking_floatingip_associate_v2" "controller" {
  count       = var.controller_count
  floating_ip = openstack_networking_floatingip_v2.controller[count.index].address
  port_id     = openstack_networking_port_v2.controller[count.index].id

  # Neutron refuses to associate a floating IP until the port's subnet has a
  # route to the external network — "ExternalGatewayForFloatingIPNotFound".
  # Nothing in the resource arguments references the router interface, so
  # without this Terraform is free to run them concurrently and the apply fails
  # on a race that looks like a permissions or quota problem.
  depends_on = [openstack_networking_router_interface_v2.router_private]
}

data "openstack_networking_network_v2" "public" {
  network_id = var.public_network_id
}

# ---------------------------------------------------------------------------
# Database (skipped entirely when external_postgres_dsn is set)
# ---------------------------------------------------------------------------

resource "openstack_networking_port_v2" "db" {
  count              = var.external_postgres_dsn == "" ? 1 : 0
  name               = "${var.name_prefix}-db-port"
  network_id         = openstack_networking_network_v2.private.id
  admin_state_up     = true
  security_group_ids = [openstack_networking_secgroup_v2.db.id]

  fixed_ip {
    subnet_id = openstack_networking_subnet_v2.private.id
  }
}

# No floating IP: the database is reachable only from the private network.
resource "openstack_compute_instance_v2" "db" {
  # Read cloud-init data from a config drive rather than only the metadata
  # service. Without it a booting instance that cannot reach 169.254.169.254 in
  # time falls back to DataSourceNone, silently skips SSH key injection, and
  # comes up ACTIVE but unreachable — observed on this exact stack.
  config_drive = true
  count        = var.external_postgres_dsn == "" ? 1 : 0
  name         = "${var.name_prefix}-db"
  flavor_name  = var.db_flavor != "" ? var.db_flavor : var.controller_flavor
  key_pair     = local.keypair_name

  block_device {
    uuid                  = data.openstack_images_image_v2.base.id
    source_type           = "image"
    destination_type      = "volume"
    volume_size           = var.db_volume_size
    volume_type           = var.volume_type
    boot_index            = 0
    delete_on_termination = false # keep the data volume if the instance is destroyed
  }

  network {
    port = openstack_networking_port_v2.db[count.index].id
  }

  lifecycle {
    ignore_changes = [block_device]
  }
}

# The Ansible inventory is generated from this single output:
#   terraform output -json geneza_inventory > ../ansible/inventory/tf.json
# (deploy.sh does it for you.)

locals {
  # WHETHER an external DSN was supplied is not itself a secret, but deriving a
  # value from a sensitive variable taints it — so unwrap explicitly. The DSN
  # itself never enters an output; Ansible receives it out of band.
  db_external = nonsensitive(var.external_postgres_dsn != "")

  controllers = [
    for i, inst in openstack_compute_instance_v2.controller : {
      name          = inst.name
      controller_id = "gw${i + 1}"
      public_ip     = openstack_networking_floatingip_v2.controller[i].address
      private_ip    = openstack_networking_port_v2.controller[i].all_fixed_ips[0]
      # Each controller advertises its OWN name — never a shared LB name. The
      # signed cluster map publishes this verbatim as the address peers use for
      # a cross-controller redirect; a shared name there sends the redirect back
      # through the balancer and the client refuses to chase a second one.
      advertise_name = "gw${i + 1}.${var.site_domain}"
    }
  ]

  home_relays = [
    for i, inst in openstack_compute_instance_v2.relay : {
      name       = inst.name
      relay_id   = inst.name
      public_ip  = openstack_networking_floatingip_v2.relay[i].address
      private_ip = openstack_networking_port_v2.relay[i].all_fixed_ips[0]
      region_id  = var.region
    }
  ]
}

output "geneza_inventory" {
  description = "Everything Ansible needs: hosts, addresses, and the facts that must not be guessed."
  value = {
    site_domain = var.site_domain
    acme_email  = var.acme_email
    controllers = local.controllers
    relays      = concat(local.home_relays, local.regional_relays)
    database = local.db_external ? {
      external   = true
      private_ip = ""
      } : {
      external   = false
      private_ip = openstack_networking_port_v2.db[0].all_fixed_ips[0]
    }
    private_cidr = var.private_cidr
  }
}

output "controller_public_ips" {
  description = "Point gw<N>.<site_domain> at these, and site_domain itself at all of them (round-robin) or at a load balancer."
  value       = { for c in local.controllers : c.advertise_name => c.public_ip }
}

output "relay_public_ips" {
  description = "Relay floating IPs. Each is admitted to the controllers' registrar port and nothing else; each relay advertises its own as public_ip for TURN."
  value       = { for r in concat(local.home_relays, local.regional_relays) : r.relay_id => r.public_ip }
}

output "dns_records_required" {
  description = "The DNS you must create before running the Ansible — Caddy's ACME challenge and the cluster map both depend on these names resolving."
  value = concat(
    [for c in local.controllers : "${c.advertise_name}  A  ${c.public_ip}"],
    [for c in local.controllers : "${var.site_domain}  A  ${c.public_ip}"],
  )
}

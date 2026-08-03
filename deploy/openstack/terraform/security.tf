# Security groups.
#
# The shape follows how Geneza actually dials:
#   agents  -> controller :7401 (mTLS gRPC control) and :7402 (CA roots, updates)
#   clients -> controller :7401, relay :7403/tcp, relay :7404/udp
#   browser -> caddy :443
#   relay   -> controller :7405  (registrar heartbeat — relays self-register)
#   gw      -> gw :7401          (cross-controller redirect + web-shell re-broker)
#
# The relay NEVER accepts a connection from a controller: registration is
# relay-initiated. So the "controller <-> relay control channel" is pinned at the
# controller's ingress, on its OWN port (:7405, cluster_control_listen), admitted
# from exactly the relay floating IPs this Terraform allocated — every region,
# every cloud. Splitting the registrar off :7401 is what makes that possible:
# :7401 must stay open to agents, :7405 must not.

locals {
  # Every relay floating IP across every region/cloud, /32'd. These are the ONLY
  # addresses permitted onto the controller registrar port.
  home_relay_fips = [for f in openstack_networking_floatingip_v2.relay : "${f.address}/32"]
  regional_relay_fips = flatten([
    for m in concat(values(module.relay_b), values(module.relay_c), values(module.relay_foreign)) :
    [for ip in m.floating_ips : "${ip}/32"]
  ])
  all_relay_fips = concat(local.home_relay_fips, local.regional_relay_fips)

  regional_relays = flatten([
    for m in concat(values(module.relay_b), values(module.relay_c), values(module.relay_foreign)) : m.relays
  ])

  # Controller floating IPs — peers reach each other here for the cross-controller
  # redirect. (Controllers ALSO resolve each other to private addresses via
  # /etc/hosts to dodge NAT hairpin; this rule is the fallback and the path a
  # controller in another failure domain would take.)
  controller_fips = [for f in openstack_networking_floatingip_v2.controller : "${f.address}/32"]

  # The two lists above hold addresses that do not exist until apply, so the
  # rules built from them CANNOT use for_each — Terraform has to know the
  # instance keys at plan time and a floating IP is not knowable then. The
  # COUNTS, however, come from variables and are static, so those rules are
  # indexed by position. (Consequence: removing a relay from the middle of a
  # region shifts indices and recreates the tail of the rules. They are
  # stateless ingress rules, so that is churn, not an outage.)
  regional_relay_count = length(var.relay_regions) == 0 ? 0 : sum([for r in var.relay_regions : r.count])
  relay_fip_count      = var.home_relay_count + local.regional_relay_count
}

# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

resource "openstack_networking_secgroup_v2" "controller" {
  name                 = "${var.name_prefix}-controller"
  description          = "Geneza controller: console, agent control, registrar"
  delete_default_rules = true
}

resource "openstack_networking_secgroup_rule_v2" "controller_egress_v4" {
  direction         = "egress"
  ethertype         = "IPv4"
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

resource "openstack_networking_secgroup_rule_v2" "controller_ssh" {
  for_each          = toset(var.admin_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# Console + ACME. This is the tenant-facing surface (hosted-UI launch lands here).
resource "openstack_networking_secgroup_rule_v2" "controller_http" {
  for_each          = toset(var.console_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

resource "openstack_networking_secgroup_rule_v2" "controller_https" {
  for_each          = toset(var.console_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# Agent/client control (mTLS gRPC) and the artifact/CA-roots HTTPS port. Agents
# dial out from anywhere, so these are as wide as var.agent_cidrs says.
resource "openstack_networking_secgroup_rule_v2" "controller_grpc" {
  for_each          = toset(var.agent_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 7401
  port_range_max    = 7402
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# Operators running the geneza CLI, when admin_cidrs is narrower than agent_cidrs.
resource "openstack_networking_secgroup_rule_v2" "controller_grpc_admin" {
  for_each          = toset(var.admin_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 7401
  port_range_max    = 7402
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# THE CONTROL CHANNEL. Relay registrar, on its own port, admitted from exactly
# the relay floating IPs — nothing else on the internet may speak to it. Adding a
# relay in a new region adds precisely one /32 here.
resource "openstack_networking_secgroup_rule_v2" "controller_registrar_from_relays" {
  count             = local.relay_fip_count
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 7405
  port_range_max    = 7405
  remote_ip_prefix  = local.all_relay_fips[count.index]
  description       = "relay registrar heartbeat"
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# Cross-controller: the redirect a non-owner controller issues, and the
# web-shell re-broker that follows it.
resource "openstack_networking_secgroup_rule_v2" "controller_peer_grpc" {
  count             = var.controller_count
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 7401
  port_range_max    = 7401
  remote_ip_prefix  = local.controller_fips[count.index]
  description       = "peer controller redirect / re-broker"
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# Everything on the private network talks freely: controller<->controller (the
# hairpin-avoiding path) and controller->database.
resource "openstack_networking_secgroup_rule_v2" "controller_private" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = var.private_cidr
  security_group_id = openstack_networking_secgroup_v2.controller.id
}

# ---------------------------------------------------------------------------
# Database — private only, reachable from the controller group and nothing else.
# ---------------------------------------------------------------------------

resource "openstack_networking_secgroup_v2" "db" {
  name                 = "${var.name_prefix}-db"
  description          = "Geneza Postgres: private only"
  delete_default_rules = true
}

resource "openstack_networking_secgroup_rule_v2" "db_egress_v4" {
  direction         = "egress"
  ethertype         = "IPv4"
  security_group_id = openstack_networking_secgroup_v2.db.id
}

resource "openstack_networking_secgroup_rule_v2" "db_postgres" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5432
  port_range_max    = 5432
  remote_group_id   = openstack_networking_secgroup_v2.controller.id
  security_group_id = openstack_networking_secgroup_v2.db.id
}

# The database has NO floating IP, so the only way to configure it is to hop
# through a controller — which arrives from the private network, not from
# admin_cidrs. Without this rule the Ansible run dies on "Connection closed by
# UNKNOWN port 65535" and the rule below looks like it should have covered it.
resource "openstack_networking_secgroup_rule_v2" "db_ssh_from_controllers" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_group_id   = openstack_networking_secgroup_v2.controller.id
  description       = "management hop from a controller"
  security_group_id = openstack_networking_secgroup_v2.db.id
}

# Only reachable if the operator later attaches a floating IP to the database;
# kept so that path works without editing the security group.
resource "openstack_networking_secgroup_rule_v2" "db_ssh" {
  for_each          = toset(var.admin_cidrs)
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.db.id
}

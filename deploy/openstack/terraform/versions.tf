terraform {
  required_version = ">= 1.6"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 2.1"
    }
  }
}

# The control plane's home region. Credentials come from the environment
# (clouds.yaml / OS_* vars) — never checked in.
provider "openstack" {
  region = var.region
}

# Additional relay regions. OpenStack providers cannot be instantiated from a
# map, so each region an operator wants relays in is declared explicitly here and
# wired to a module call in relays.tf. Two extra regions are pre-declared; copy
# the pattern for more. A region left out of var.relay_regions costs nothing.
provider "openstack" {
  alias  = "relay_b"
  region = var.relay_region_b
}

provider "openstack" {
  alias  = "relay_c"
  region = var.relay_region_c
}

# A relay may live in an entirely different CLOUD (its own Keystone), not just
# another region. Point these at that cloud's clouds.yaml entry; auth then comes
# from `cloud = ...` rather than the ambient OS_* environment.
provider "openstack" {
  alias  = "relay_foreign"
  cloud  = var.foreign_relay_cloud
  region = var.foreign_relay_region
}

output "floating_ips" {
  description = "Relay floating IPs. The root module turns these into the /32 allow-list on the controllers' registrar port."
  value       = openstack_networking_floatingip_v2.relay[*].address
}

output "relays" {
  description = "Ansible inventory rows for this region's relays."
  value = [
    for i, inst in openstack_compute_instance_v2.relay : {
      name        = inst.name
      relay_id    = inst.name
      public_ip   = openstack_networking_floatingip_v2.relay[i].address
      private_ip  = openstack_networking_port_v2.relay[i].all_fixed_ips[0]
      region_id   = var.region_id
      volume_type = var.volume_type
    }
  ]
}

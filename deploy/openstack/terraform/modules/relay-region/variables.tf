variable "name_prefix" { type = string }
variable "image_name" { type = string }
variable "flavor" { type = string }
variable "keypair_name" { type = string }
variable "public_network_id" { type = string }
variable "volume_type" { type = string }

# `count` is reserved as a meta-argument, hence the trailing underscore.
variable "count_" {
  description = "Relays to create in this region."
  type        = number
  default     = 2
}

variable "volume_size" {
  type    = number
  default = 20
}

variable "private_cidr" {
  type    = string
  default = "10.43.0.0/24"
}

variable "dns_nameservers" {
  type    = list(string)
  default = ["1.1.1.1", "9.9.9.9"]
}

variable "admin_cidrs" {
  type    = list(string)
  default = []
}

variable "anti_affinity_policy" {
  type    = string
  default = "soft-anti-affinity"
}

variable "region_id" {
  description = "Geneza region tag for these relays. A relay only validates TURN credentials minted for its own region, so this must match the controller's relay_secrets entry."
  type        = string
  default     = ""
}

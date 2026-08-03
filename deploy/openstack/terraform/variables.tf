# ---------------------------------------------------------------------------
# Placement / sizing
# ---------------------------------------------------------------------------

variable "region" {
  description = "Region hosting the control plane (controllers + database)."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for every created resource; also the Geneza controller-id stem (gw1, gw2, …)."
  type        = string
  default     = "geneza"
}

variable "image_name" {
  description = "Base image for every instance. Ubuntu 24.04 LTS is what the Ansible expects."
  type        = string
  default     = "Ubuntu 24.04"
}

variable "controller_flavor" {
  description = "Flavor for controller instances."
  type        = string
}

variable "relay_flavor" {
  description = "Flavor for relay instances. Relays are stateless byte-shovels: CPU and NIC matter, disk does not."
  type        = string
}

variable "db_flavor" {
  description = "Flavor for the self-hosted Postgres instance. Ignored when external_postgres_dsn is set."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Storage — instances ALWAYS boot from volume (ephemeral root is not used), so a
# rebuild keeps the disk and the flavor's local disk never bounds us.
# ---------------------------------------------------------------------------

variable "volume_type" {
  description = "Cinder volume type for the boot volume (e.g. classic, high-speed, high-speed-gen2)."
  type        = string
}

variable "controller_volume_size" {
  description = "Controller boot volume size (GB). Holds the CA, bbolt/no-op state, audit chain and logs."
  type        = number
  default     = 40
}

variable "relay_volume_size" {
  description = "Relay boot volume size (GB). Relays hold no session state; this is OS + logs only."
  type        = number
  default     = 20
}

variable "db_volume_size" {
  description = "Postgres boot volume size (GB)."
  type        = number
  default     = 100
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

variable "public_network_id" {
  description = "External network the router uplinks to and floating IPs are allocated from (OVH: Ext-Net)."
  type        = string
}

variable "private_cidr" {
  description = "CIDR for the created private network. Controllers reach each other and the database over this."
  type        = string
  default     = "10.42.0.0/24"
}

variable "dns_nameservers" {
  description = "Resolvers handed to instances by DHCP."
  type        = list(string)
  default     = ["213.186.33.99", "1.1.1.1"]
}

variable "ssh_public_key" {
  description = "SSH public key material to register as a Nova keypair. Mutually exclusive with ssh_keypair_name."
  type        = string
  default     = ""
}

variable "ssh_keypair_name" {
  description = "Name of a keypair that ALREADY exists in the cloud. Takes precedence over ssh_public_key."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Fleet shape
# ---------------------------------------------------------------------------

variable "controller_count" {
  description = "Number of controllers. HA needs >= 2; 3 tolerates one loss while keeping a majority of hosts for anti-affinity."
  type        = number
  default     = 3
}

variable "anti_affinity_policy" {
  description = "Server-group policy for controllers. Hard 'anti-affinity' fails the build if the region cannot place them on distinct hosts; 'soft-anti-affinity' degrades instead. Prefer hard, and only fall back if the region refuses."
  type        = string
  default     = "anti-affinity"

  validation {
    condition     = contains(["anti-affinity", "soft-anti-affinity"], var.anti_affinity_policy)
    error_message = "anti_affinity_policy must be anti-affinity or soft-anti-affinity."
  }
}

variable "home_relay_count" {
  description = "Relays in the control-plane region. Zero is valid if every relay lives elsewhere."
  type        = number
  default     = 2
}

variable "relay_regions" {
  description = <<-EOT
    Relays outside the home region, keyed by the provider alias declared in
    versions.tf: "relay_b", "relay_c", "relay_foreign". Each entry sets its own
    count/flavor/volume and the public network to draw floating IPs from — those
    IDs are per-cloud, so a foreign cloud needs its own.

    A relay in another cloud still registers to the SAME controllers over the
    public control channel, and the controller security group admits exactly its
    floating IP.
  EOT
  type = map(object({
    count             = number
    flavor            = string
    public_network_id = string
    volume_type       = string
    volume_size       = optional(number, 20)
    private_cidr      = optional(string, "10.43.0.0/24")
    region_id         = optional(string, "")
  }))
  default = {}
}

variable "relay_region_b" {
  description = "Region for the relay_b provider alias."
  type        = string
  default     = ""
}

variable "relay_region_c" {
  description = "Region for the relay_c provider alias."
  type        = string
  default     = ""
}

variable "foreign_relay_cloud" {
  description = "clouds.yaml entry for a relay in a DIFFERENT cloud/Keystone."
  type        = string
  default     = ""
}

variable "foreign_relay_region" {
  description = "Region within foreign_relay_cloud."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

variable "admin_cidrs" {
  description = "CIDRs allowed to SSH and to reach the controller gRPC API (operators running the geneza CLI). Keep this tight; it is not the tenant-facing surface."
  type        = list(string)
  default     = []
}

variable "console_cidrs" {
  description = "CIDRs allowed to reach the web console over 80/443. Default is the whole internet, which is the point of a hosted UI — narrow it for a private deployment."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "agent_cidrs" {
  description = "CIDRs your agents dial in from, for controller :7402 (CA roots, updates) and :7401 (control). Agents are usually anywhere, hence the default."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ---------------------------------------------------------------------------
# Geneza configuration passed through to Ansible
# ---------------------------------------------------------------------------

variable "site_domain" {
  description = "Public domain for the console, e.g. geneza.example.com. Caddy takes a Let's Encrypt cert for this and for each controller's own name."
  type        = string
}

variable "acme_email" {
  description = "Contact address for Let's Encrypt."
  type        = string
}

variable "external_postgres_dsn" {
  description = "Managed-Postgres DSN. When set, no database instance is created — strongly preferred, since Postgres is the one component whose HA you must provide yourself."
  type        = string
  default     = ""
  sensitive   = true
}

# Some clouds attach SEVERAL external subnets to one public network, with
# different routing, different regions, or different exhaustion. Leaving this
# empty lets Neutron pick any of them, which is fine until one of those ranges
# is not globally announced — the instance then comes up with a floating IP that
# simply cannot be reached, and nothing in the API says so. Pin the subnet when
# the cloud has more than one.
variable "public_subnet_id" {
  description = "External subnet to allocate floating IPs from. Empty = let Neutron choose."
  type        = string
  default     = ""
}

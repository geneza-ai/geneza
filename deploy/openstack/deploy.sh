#!/usr/bin/env bash
# Terraform apply -> inventory -> Ansible, in the order the dependencies demand.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TF="$HERE/terraform"
ANS="$HERE/ansible"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

step "terraform apply"
terraform -chdir="$TF" init -input=false
terraform -chdir="$TF" apply -input=false "$@"

step "generating the Ansible inventory from Terraform outputs"
terraform -chdir="$TF" output -json geneza_inventory > "$ANS/inventory/tf.json"

# The cluster map advertises per-controller names, and Caddy needs each to
# resolve before it can complete an ACME challenge. Failing here is far cheaper
# than a half-provisioned control plane with no certificates.
step "checking DNS"
missing=0
while read -r name ip; do
  got="$(dig +short "$name" A | tail -1 || true)"
  if [ -z "$got" ]; then
    echo "  MISSING  $name (expected $ip)"; missing=1
  elif [ "$got" != "$ip" ]; then
    echo "  MISMATCH $name -> $got (expected $ip)"; missing=1
  else
    echo "  ok       $name -> $ip"
  fi
done < <(terraform -chdir="$TF" output -json controller_public_ips | jq -r 'to_entries[] | "\(.key) \(.value)"')
if [ "$missing" = 1 ]; then
  echo
  echo "Create the records above, then re-run. Each controller must resolve at its"
  echo "OWN name: that name is what the signed cluster map hands peers on a"
  echo "cross-controller redirect, and what its TLS cert is verified against."
  exit 1
fi

step "ansible"
cd "$ANS"

# Ansible needs the PRIVATE half of var.ssh_public_key. Terraform only ever sees
# the public half and the inventory is generated from Terraform, so nothing in
# this repo can discover it — it has to come from the environment. Without it
# every host is UNREACHABLE with a bare "Permission denied (publickey)" that
# says nothing about which key was missing.
if [ -n "${GENEZA_SSH_KEY:-}" ]; then
  export ANSIBLE_PRIVATE_KEY_FILE="$GENEZA_SSH_KEY"
elif [ -z "${ANSIBLE_PRIVATE_KEY_FILE:-}" ] && ! ssh-add -l >/dev/null 2>&1; then
  echo "  no SSH key: set GENEZA_SSH_KEY=/path/to/private_key (the private half of"
  echo "  var.ssh_public_key), or load it into ssh-agent, then re-run."
  exit 1
fi
# ANSIBLE_ARGS must not be quoted into a single argument: when it is unset,
# "${ANSIBLE_ARGS:-}" expands to one EMPTY argument, which ansible-playbook
# reads as a second playbook name and dies with "the playbook: could not be
# found". Split it deliberately instead.
secrets=()
[ -f secrets.yml ] && secrets=(-e @secrets.yml)

if [ -n "${ANSIBLE_ARGS:-}" ]; then
  # shellcheck disable=SC2086 # word splitting is the point here
  ansible-playbook -i inventory/tf_inventory.py "${secrets[@]+"${secrets[@]}"}" site.yml $ANSIBLE_ARGS
else
  ansible-playbook -i inventory/tf_inventory.py "${secrets[@]+"${secrets[@]}"}" site.yml
fi

step "done"
terraform -chdir="$TF" output relay_public_ips

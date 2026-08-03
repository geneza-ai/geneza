#!/usr/bin/env python3
"""Ansible dynamic inventory from `terraform output -json geneza_inventory`.

Reads tf.json (written by deploy.sh) and emits groups `controllers`, `relays`,
`database`. Every host gets the facts that MUST NOT be guessed at config time:

  - `advertise_name`   each controller's OWN public name. It is published into
                       the signed cluster map verbatim and is what a peer dials
                       on a cross-controller redirect. A shared load-balancer
                       name here breaks redirects (the peer can be sent back to
                       the controller that just redirected it, and a client
                       refuses to chase a second redirect).
  - `public_ip`        for a relay this becomes `public_ip` in relay.yaml. The
                       TURN server advertises it STATICALLY to clients, and the
                       instance itself only ever sees its private address behind
                       the floating IP's 1:1 NAT — so if this is wrong, TURN
                       hands out an unroutable address and UDP silently fails.
  - `private_ip`       used for the /etc/hosts entries that keep
                       controller-to-controller traffic off the hairpin path.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TF_JSON = os.environ.get("GENEZA_TF_JSON", os.path.join(HERE, "tf.json"))

# Must match ansible.cfg's remote_user: it is also the user for the jump host
# hop to the database, which has no floating IP.
SSH_USER = os.environ.get("GENEZA_SSH_USER", "ubuntu")

# The private key, if the operator named one. deploy.sh exports
# ANSIBLE_PRIVATE_KEY_FILE from GENEZA_SSH_KEY.
SSH_KEY = os.environ.get("ANSIBLE_PRIVATE_KEY_FILE") or os.environ.get("GENEZA_SSH_KEY", "")


def jump_args(jump_host):
    """SSH args that reach a private host through a controller.

    ProxyJump alone is not enough when the key is passed explicitly: it spawns a
    SECOND ssh process that does not inherit Ansible's --private-key, so the hop
    fails with "Connection closed by UNKNOWN port 65535" while the same key
    works fine against the controllers. When a key path is known, spell the hop
    out as a ProxyCommand carrying that key; otherwise fall back to ProxyJump
    and let ssh-agent answer for both legs.
    """
    common = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    if SSH_KEY:
        inner = "ssh -i %s -W %%h:%%p %s %s@%s" % (
            os.path.expanduser(SSH_KEY), common, SSH_USER, jump_host)
        return '-o ProxyCommand="%s" %s' % (inner, common)
    return "-o ProxyJump=%s@%s %s" % (SSH_USER, jump_host, common)


def load():
    with open(TF_JSON) as fh:
        doc = json.load(fh)
    # Accept both `terraform output -json` (wrapped in {"value": ...}) and a
    # pre-unwrapped file.
    return doc.get("value", doc)


def build(tf):
    controllers = tf["controllers"]
    relays = tf["relays"]

    inv = {
        "_meta": {"hostvars": {}},
        "controllers": {"hosts": []},
        "relays": {"hosts": []},
        "database": {"hosts": []},
        "geneza": {"children": ["controllers", "relays", "database"]},
    }

    # Peers each controller must resolve PRIVATELY: name -> private ip. The
    # controller dials a sibling by its advertised name (so TLS verifies), but
    # resolves that name to the private address, sidestepping NAT hairpin.
    peer_hosts = {c["advertise_name"]: c["private_ip"] for c in controllers}

    for c in controllers:
        inv["controllers"]["hosts"].append(c["name"])
        inv["_meta"]["hostvars"][c["name"]] = {
            "ansible_host": c["public_ip"],
            "controller_id": c["controller_id"],
            "advertise_name": c["advertise_name"],
            "public_ip": c["public_ip"],
            "private_ip": c["private_ip"],
            "peer_hosts": peer_hosts,
            "site_domain": tf["site_domain"],
            "acme_email": tf["acme_email"],
            "controller_peers": [
                x["advertise_name"] for x in controllers if x["name"] != c["name"]
            ],
        }

    for r in relays:
        inv["relays"]["hosts"].append(r["name"])
        inv["_meta"]["hostvars"][r["name"]] = {
            "ansible_host": r["public_ip"],
            "relay_id": r["relay_id"],
            "public_ip": r["public_ip"],
            "private_ip": r["private_ip"],
            "region_id": r.get("region_id") or "default",
            # Not used by the relay config itself, but group_vars interpolate it
            # (geneza_local_ca_dir is namespaced by site) and a lazily-evaluated
            # undefined variable would blow up on whichever task touches it first.
            "site_domain": tf["site_domain"],
            # Relays register to every controller's registrar and fail over
            # between them; the first is only the bootstrap entry.
            "registrar_addrs": [
                "%s:7405" % c["advertise_name"] for c in controllers
            ],
        }

    db = tf.get("database") or {}
    if not db.get("external", True) and db.get("private_ip"):
        inv["database"]["hosts"].append("geneza-db")
        inv["_meta"]["hostvars"]["geneza-db"] = {
            # No floating IP by design: the database is reachable only from
            # inside the private network, so Ansible has to hop through a
            # controller to configure it. Without this the play fails trying to
            # open an SSH connection straight to a private address.
            "ansible_host": db["private_ip"],
            "private_ip": db["private_ip"],
            "private_cidr": tf.get("private_cidr", ""),
            "ansible_ssh_common_args": jump_args(controllers[0]["public_ip"]),
        }
    return inv


def main():
    if "--host" in sys.argv:
        print(json.dumps({}))
        return
    print(json.dumps(build(load()), indent=2))


if __name__ == "__main__":
    main()

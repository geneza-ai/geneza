#!/usr/bin/env bash
# Set up a SoftHSM2 token with two ECDSA P-256 keys (issuing CA + agent node
# identity) and an Ed25519 key (grant), then export the GENEZA_TEST_PKCS11_*
# variables the keysource and agentd pkcs11 tests read. Source this script, then
# run the tests:
#
#   source scripts/softhsm-test.sh
#   go test ./internal/keysource/ -run PKCS11 -v
#   go test ./internal/agentd/   -run NodeKeyPKCS11 -v
#
# Requires softhsm2 + opensc (Debian: apt-get install -y softhsm2 opensc).
# The token lives in a throwaway dir; re-sourcing re-initializes it.

set -euo pipefail

KS_DIR="${KS_DIR:-/tmp/geneza-softhsm}"
KS_PIN="${KS_PIN:-1234}"
KS_SOPIN="${KS_SOPIN:-5678}"
KS_TOKEN="${KS_TOKEN:-geneza-test}"

MODULE=""
for cand in \
	/usr/lib/softhsm/libsofthsm2.so \
	/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
	/usr/local/lib/softhsm/libsofthsm2.so; do
	if [ -f "$cand" ]; then MODULE="$cand"; break; fi
done
if [ -z "$MODULE" ]; then
	echo "libsofthsm2.so not found (install softhsm2)" >&2
	return 1 2>/dev/null || exit 1
fi

rm -rf "$KS_DIR"
mkdir -p "$KS_DIR/tokens"
export SOFTHSM2_CONF="$KS_DIR/softhsm2.conf"
cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $KS_DIR/tokens
objectstore.backend = file
log.level = ERROR
EOF

softhsm2-util --init-token --free --label "$KS_TOKEN" --pin "$KS_PIN" --so-pin "$KS_SOPIN" >/dev/null

# Issuing-CA key: ECDSA P-256 (works on every PKCS#11 token).
pkcs11-tool --module "$MODULE" --token-label "$KS_TOKEN" --login --pin "$KS_PIN" \
	--keypairgen --key-type EC:prime256v1 --label geneza-ca --id 01 >/dev/null

# Agent node identity key: ECDSA P-256, a distinct on-token key found by label.
# The node key is ECDSA, so this sign-in-place path is fully supported.
pkcs11-tool --module "$MODULE" --token-label "$KS_TOKEN" --login --pin "$KS_PIN" \
	--keypairgen --key-type EC:prime256v1 --label geneza-node --id 03 >/dev/null

# Grant key: Ed25519 (CKM_EDDSA). Only succeeds on an EdDSA-capable token; if it
# fails, the CA path still works and the grant pkcs11 test stays skipped.
GRANT_OK=0
if pkcs11-tool --module "$MODULE" --token-label "$KS_TOKEN" --login --pin "$KS_PIN" \
	--keypairgen --key-type EC:edwards25519 --label geneza-grant --id 02 >/dev/null 2>&1; then
	GRANT_OK=1
fi

export GENEZA_TEST_PKCS11_MODULE="$MODULE"
export GENEZA_TEST_PKCS11_PIN="$KS_PIN"
export GENEZA_TEST_PKCS11_TOKEN="$KS_TOKEN"
export GENEZA_TEST_PKCS11_CA_LABEL="geneza-ca"
export GENEZA_TEST_PKCS11_NODE_LABEL="geneza-node"
if [ "$GRANT_OK" = "1" ]; then
	export GENEZA_TEST_PKCS11_GRANT_LABEL="geneza-grant"
	echo "SoftHSM token ready: ECDSA (geneza-ca) + Ed25519 (geneza-grant)."
else
	unset GENEZA_TEST_PKCS11_GRANT_LABEL || true
	echo "SoftHSM token ready: ECDSA (geneza-ca) only — token has no EdDSA, grant pkcs11 test will skip."
fi
echo "Module: $MODULE  Token: $KS_TOKEN"

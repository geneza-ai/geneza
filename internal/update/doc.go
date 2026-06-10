// Package update implements the security-critical pieces of Geneza's
// two-stage self-update path (ARCHITECTURE.md §9): persisted updater state,
// offline-signature-verified artifact installation, child-process
// supervision with restart backoff, the post-swap health gate, and
// version-directory pruning.
//
// This package is linked into geneza-bootstrap, which must stay tiny and
// auditable. Only the Go standard library plus internal/types and
// internal/defaults may be imported here — no gRPC, no cobra, no YAML.
//
// Trust model: the binary trust decision rests EXCLUSIVELY on the ed25519
// artifact signing key pinned on the node, never on the gateway's TLS. A
// fully compromised gateway can at worst serve stale-but-valid manifests;
// it can never get an unsigned or altered binary installed.
package update

// geneza-sign is the OFFLINE artifact signing tool (ARCHITECTURE.md §9).
// It runs on the operator's machine or secrets host — NEVER on the controller.
// The private key it produces is one of the system's crown jewels: whoever
// holds it can push code to the entire fleet. The controller only ever sees the
// resulting signed manifests and blobs.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"geneza.io/internal/defaults"
	"geneza.io/internal/releasetrust"
	"geneza.io/internal/types"
	"geneza.io/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:           "geneza-sign",
		Short:         "Offline Geneza artifact signing (keygen, manifest, verify)",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(keygenCmd(), manifestCmd(), verifyCmd(), rootKeysCmd(), verifyChainCmd(), signFileCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func keygenCmd() *cobra.Command {
	var outDir, name string
	cmd := &cobra.Command{
		Use:   "keygen --out-dir DIR [--name root|signer1|...]",
		Short: "Generate a signing keypair (<name>.key/.pub/.keyid). Use --name root for the offline trust root, --name signerN for rotatable release keys.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				name = "artifact"
			}
			keyPath := filepath.Join(outDir, name+".key")
			pubPath := filepath.Join(outDir, name+".pub")
			idPath := filepath.Join(outDir, name+".keyid")
			// Refuse to overwrite: clobbering the fleet's signing key by
			// accident is unrecoverable without re-touching every node.
			for _, p := range []string{keyPath, pubPath, idPath} {
				if _, err := os.Stat(p); err == nil {
					return fmt.Errorf("refusing to overwrite existing %s", p)
				}
			}
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return err
			}
			pub, priv, keyID, err := types.GenerateSigningKey()
			if err != nil {
				return err
			}
			if err := types.SavePrivateKeyPEM(keyPath, priv); err != nil { // 0600
				return err
			}
			if err := types.SavePublicKeyPEM(pubPath, pub); err != nil {
				return err
			}
			if err := os.WriteFile(idPath, []byte(keyID+"\n"), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "key id: %s\nprivate key: %s (keep OFFLINE)\npublic key: %s (pin on every node)\n",
				keyID, keyPath, pubPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory to write <name>.key/.pub/.keyid into")
	cmd.Flags().StringVar(&name, "name", "artifact", "key name (e.g. root, signer1)")
	_ = cmd.MarkFlagRequired("out-dir")
	return cmd
}

// signFileCmd offline-signs a release file (the SHA256SUMS manifest) with a
// release-signing key, emitting a detached signature the client self-update and
// the controller agent-pull verify against the pinned root via root-keys.json.
func signFileCmd() *cobra.Command {
	var keyPath, filePath, outPath, tag string
	cmd := &cobra.Command{
		Use:   "sign-file --key signerN.key --file SHA256SUMS --tag vX.Y.Z --out SHA256SUMS.sig",
		Short: "Offline-sign a release file (e.g. SHA256SUMS) with a release-signing key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := types.LoadPrivateKeyPEM(keyPath)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			signed, err := releasetrust.SignSums(priv, tag, data)
			if err != nil {
				return err
			}
			out, err := signed.Encode()
			if err != nil {
				return err
			}
			if err := os.WriteFile(outPath, append(out, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signed %s -> %s (key %s)\n",
				filePath, outPath, types.KeyIDFor(priv.Public().(ed25519.PublicKey)))
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "release-signing private key (signerN.key)")
	cmd.Flags().StringVar(&filePath, "file", "", "file to sign (e.g. SHA256SUMS)")
	cmd.Flags().StringVar(&tag, "tag", "", "release tag the signature is bound to (e.g. vX.Y.Z)")
	cmd.Flags().StringVar(&outPath, "out", "", "detached signature output path")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// rootKeysCmd builds and offline-signs the RootKeys trust document: the root
// key authorizes the current set of release-signing keys. Rotating a signing
// key = re-running this with a bumped --version and the new --signer-pub set.
func rootKeysCmd() *cobra.Command {
	var rootKeyPath, outPath string
	var signerPubs []string
	var version int64
	var expiresDays int
	cmd := &cobra.Command{
		Use:   "root-keys --root-key root.key --signer-pub signer1.pub [--signer-pub signer2.pub] --version N --out root-keys.json",
		Short: "Sign the artifact trust root: the rotatable set of release-signing keys, authorized by the offline root key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rootPriv, err := types.LoadPrivateKeyPEM(rootKeyPath)
			if err != nil {
				return err
			}
			rootID := types.KeyIDFor(rootPriv.Public().(ed25519.PublicKey))
			if len(signerPubs) == 0 {
				return fmt.Errorf("at least one --signer-pub is required")
			}
			rk := types.RootKeys{Version: version}
			for _, p := range signerPubs {
				pub, err := types.LoadPublicKeyPEM(p)
				if err != nil {
					return fmt.Errorf("load signer pub %s: %w", p, err)
				}
				rk.Keys = append(rk.Keys, types.ArtifactKey{KeyID: types.KeyIDFor(pub), PublicKey: pub})
			}
			if expiresDays > 0 {
				rk.ExpiresAt = time.Now().UTC().Add(time.Duration(expiresDays) * 24 * time.Hour)
			}
			signed, err := types.Sign(rootPriv, rootID, defaults.ContextRootKeys, &rk)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(signed, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(outPath, append(out, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signed root-keys v%d: %d signing key(s), root=%s, expires=%s -> %s\n",
				rk.Version, len(rk.Keys), rootID, rk.ExpiresAt.Format(time.RFC3339), outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&rootKeyPath, "root-key", "", "offline ROOT private key (root.key)")
	cmd.Flags().StringArrayVar(&signerPubs, "signer-pub", nil, "release-signing public key(s) to authorize (repeatable)")
	cmd.Flags().Int64Var(&version, "version", 1, "monotonic root-keys version (bump on every rotation)")
	cmd.Flags().IntVar(&expiresDays, "expires-days", 365, "days until this trust root expires (0 = never)")
	cmd.Flags().StringVar(&outPath, "out", "root-keys.json", "output signed root-keys path")
	_ = cmd.MarkFlagRequired("root-key")
	return cmd
}

// verifyChainCmd does exactly what an agent does: pin the root, verify
// root-keys -> derive signing set -> verify the manifest -> verify the binary.
func verifyChainCmd() *cobra.Command {
	var rootPubPath, rootKeysPath, manifestPath, binPath string
	cmd := &cobra.Command{
		Use:   "verify-chain --root-pub root.pub --root-keys root-keys.json --manifest m.json --binary PATH",
		Short: "Verify the full trust chain (root -> signing keys -> manifest -> binary), as the agent does",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rootPub, err := types.LoadPublicKeyPEM(rootPubPath)
			if err != nil {
				return err
			}
			rkRaw, err := os.ReadFile(rootKeysPath)
			if err != nil {
				return err
			}
			rkSigned, err := types.DecodeSigned(rkRaw)
			if err != nil {
				return err
			}
			mRaw, err := os.ReadFile(manifestPath)
			if err != nil {
				return err
			}
			mSigned, err := types.DecodeSigned(mRaw)
			if err != nil {
				return err
			}
			pinned := map[string]ed25519.PublicKey{types.KeyIDFor(rootPub): rootPub}
			rk, m, err := types.VerifyArtifactChain(pinned, rkSigned, mSigned, 0, time.Now())
			if err != nil {
				return err
			}
			f, err := os.Open(binPath)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := m.VerifyBlob(f); err != nil {
				return fmt.Errorf("binary does not match manifest: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: chain verifies — root-keys v%d (%d signers) -> %s %s (%s/%s) sha256=%s key_id=%s\n",
				rk.Version, len(rk.Keys), m.Product, m.Version, m.OS, m.Arch, m.SHA256, mSigned.KeyID)
			return nil
		},
	}
	cmd.Flags().StringVar(&rootPubPath, "root-pub", "", "pinned ROOT public key (root.pub)")
	cmd.Flags().StringVar(&rootKeysPath, "root-keys", "", "signed root-keys.json")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "signed manifest JSON")
	cmd.Flags().StringVar(&binPath, "binary", "", "binary to verify against the manifest")
	_ = cmd.MarkFlagRequired("root-pub")
	_ = cmd.MarkFlagRequired("root-keys")
	_ = cmd.MarkFlagRequired("manifest")
	_ = cmd.MarkFlagRequired("binary")
	return cmd
}

func manifestCmd() *cobra.Command {
	var (
		keyPath, binPath, product, ver, osName, arch, outPath string
	)
	cmd := &cobra.Command{
		Use:   "manifest --key artifact.key --binary PATH --product geneza-agent --version V --out signed-manifest.json",
		Short: "Hash a built binary and emit an offline-signed manifest",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := types.LoadPrivateKeyPEM(keyPath)
			if err != nil {
				return err
			}
			keyID := types.KeyIDFor(priv.Public().(ed25519.PublicKey))

			f, err := os.Open(binPath)
			if err != nil {
				return err
			}
			defer f.Close()
			h := sha256.New()
			size, err := io.Copy(h, f)
			if err != nil {
				return fmt.Errorf("hashing %s: %w", binPath, err)
			}
			m := types.Manifest{
				Product:   product,
				Version:   ver,
				OS:        osName,
				Arch:      arch,
				SHA256:    hex.EncodeToString(h.Sum(nil)),
				Size:      size,
				CreatedAt: time.Now().UTC(),
			}
			signed, err := types.Sign(priv, keyID, defaults.ContextManifest, &m)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(signed, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(outPath, append(out, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signed %s %s (%s/%s) sha256=%s size=%d key_id=%s -> %s\n",
				m.Product, m.Version, m.OS, m.Arch, m.SHA256, m.Size, keyID, outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "artifact signing private key (artifact.key)")
	cmd.Flags().StringVar(&binPath, "binary", "", "built worker binary to hash")
	cmd.Flags().StringVar(&product, "product", "geneza-agent", "product name")
	cmd.Flags().StringVar(&ver, "version", "", "artifact version, e.g. 0.2.0")
	cmd.Flags().StringVar(&osName, "os", "linux", "target GOOS")
	cmd.Flags().StringVar(&arch, "arch", "amd64", "target GOARCH")
	cmd.Flags().StringVar(&outPath, "out", "signed-manifest.json", "output signed manifest path")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("binary")
	_ = cmd.MarkFlagRequired("version")
	return cmd
}

func verifyCmd() *cobra.Command {
	var pubPath, manifestPath, binPath string
	cmd := &cobra.Command{
		Use:   "verify --pub artifact.pub --manifest signed-manifest.json --binary PATH",
		Short: "Verify a signed manifest and the binary it describes (what the bootstrap will do)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, err := types.LoadPublicKeyPEM(pubPath)
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				return err
			}
			signed, err := types.DecodeSigned(raw)
			if err != nil {
				return err
			}
			var m types.Manifest
			if err := types.VerifyOne(pub, "", defaults.ContextManifest, signed, &m); err != nil {
				return fmt.Errorf("manifest signature: %w", err)
			}
			f, err := os.Open(binPath)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := m.VerifyBlob(f); err != nil {
				return fmt.Errorf("binary does not match manifest: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: %s %s (%s/%s) sha256=%s size=%d key_id=%s\n",
				m.Product, m.Version, m.OS, m.Arch, m.SHA256, m.Size, signed.KeyID)
			return nil
		},
	}
	cmd.Flags().StringVar(&pubPath, "pub", "", "artifact public key (artifact.pub)")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "signed manifest JSON")
	cmd.Flags().StringVar(&binPath, "binary", "", "binary to verify against the manifest")
	_ = cmd.MarkFlagRequired("pub")
	_ = cmd.MarkFlagRequired("manifest")
	_ = cmd.MarkFlagRequired("binary")
	return cmd
}

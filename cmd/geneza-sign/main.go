// geneza-sign is the OFFLINE artifact signing tool (ARCHITECTURE.md §9).
// It runs on the operator's machine or secrets host — NEVER on the gateway.
// The private key it produces is one of the system's crown jewels: whoever
// holds it can push code to the entire fleet. The gateway only ever sees the
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

	"osie.cloud/geneza/internal/defaults"
	"osie.cloud/geneza/internal/types"
	"osie.cloud/geneza/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:           "geneza-sign",
		Short:         "Offline Geneza artifact signing (keygen, manifest, verify)",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(keygenCmd(), manifestCmd(), verifyCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func keygenCmd() *cobra.Command {
	var outDir string
	cmd := &cobra.Command{
		Use:   "keygen --out-dir DIR",
		Short: "Generate a new artifact signing keypair (artifact.key/.pub/.keyid)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyPath := filepath.Join(outDir, "artifact.key")
			pubPath := filepath.Join(outDir, "artifact.pub")
			idPath := filepath.Join(outDir, "artifact.keyid")
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
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory to write artifact.key/.pub/.keyid into")
	_ = cmd.MarkFlagRequired("out-dir")
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
